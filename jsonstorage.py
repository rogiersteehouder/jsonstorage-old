#!/usr/bin/env python3
# encoding: UTF-8

"""JSON storage webservice

Provides REST webservices (with FastAPI) to store and retrieve json objects.
"""

__author__  = 'Rogier Steehouder'
__date__    = '2022-01-12'
__version__ = '1.1'

# TODO: etag

import sys
import contextlib
import datetime
import getpass
import json
import sqlite3
import uuid
from pathlib import Path
from typing import List

import uvicorn
from fastapi import FastAPI, Depends, APIRouter, Request, Query, Body, Response, status, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from loguru import logger
from passlib.context import CryptContext

# Optional for patch operation
try:
    import jsonpatch
except:
    jsonpatch = None
# Optional for yaml config
try:
    from ruamel.yaml import YAML
    yaml = YAML(pure=True)
    yaml.default_flow_style = False
except:
    yaml = None
# Optional for toml config
try:
    import toml
except:
    toml = None


#####
# Configuration
#####
class Config:
    """Config class

    Can read/save json, yaml or toml.
    Use dot notation to get subkeys.
    """
    def __init__(self, cfgfile):
        path = Path(cfgfile)
        if path.is_dir():
            try:
                path = next(path.glob('config.*'))
            except StopIteration:
                path = path / 'config.yaml'
        if not path.exists():
            path.touch()

        self.path = path
        self.load()

    @property
    def path(self):
        """File path of the config file"""
        return self._path
    @path.setter
    def path(self, p):
        self._path = Path(p)
        self.yaml = (yaml and self._path.suffix == '.yaml')
        self.toml = (toml and self._path.suffix == '.toml')

    def load(self):
        """Load config from file"""
        content = self.path.read_text()
        if not content:
            self._config = {}
        elif self.yaml:
            self._config = yaml.load(content)
        elif self.toml:
            self._config = toml.loads(content)
        else:
            self._config = json.loads(content)

    def save(self):
        """Save config to file"""
        if self.yaml:
            yaml.dump(self._config, self.path)
        elif self.toml:
            self.path.write_text(toml.dumps(self._config))
        else:
            self.path.write_text(json.dumps(self._config, indent='\t'))

    def __parent(self, keys, set_default=False):
        """Get the parent dict for a compound key"""
        p = self._config
        if set_default:
            for k in keys[:-1]:
                p = p.setdefault(k, {})
        else:
            for k in keys[:-1]:
                p = p[k]
        return p

    def __getitem__(self, key):
        """Get a config value"""
        keys = key.split('.')
        try:
            p = self.__parent(keys)
            return p[keys[-1]]
        except KeyError:
            raise KeyError(key)

    def __setitem__(self, key, val):
        """Set a config value"""
        keys = key.split('.')
        p = self.__parent(keys, set_default=True)
        p[keys[-1]] = val

    def __delitem__(self, key):
        """Remove a config value
        
        This may leave empty dicts behind.
        """
        keys = key.split('.')
        try:
            p = self.__parent(keys)
            del p[keys[-1]]
        except KeyError:
            raise KeyError(key)

    def get(self, key, default=None, set_default=False):
        """Get a config value"""
        try:
            return self[key]
        except KeyError:
            if set_default:
                p[key] = default
            return default


#####
# Basic authentication with password only
#####
class Security:
    context = CryptContext(['pbkdf2_sha256'])

    """Basic single user authentication for FastAPI
    
    Use a callback function to save a changed password hash when needed.
    Add security.valid_password as a dependency.
    """
    def __init__(self, hash: str, *, period: int = 0, new_hash: callable = None, logger: 'loguru._logger.Logger'):
        self.hash = hash
        self.new_hash = new_hash
        self.logger = logger

        self.period = None
        if period > 0:
            # For websites: ask for password after x minutes of inactivity
            self.renew = datetime.datetime.min
            self.period = datetime.timedelta(minutes=period)

    def valid_password(self, credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
        """Password dependency for FastAPI"""
        ok, new_hash = self.context.verify_and_update(credentials.password, self.hash)
        if self.period is not None:
            ok = (ok and self.renew > datetime.datetime.now())
            self.renew = datetime.datetime.now() + self.period
        if not ok:
            self.logger.warning('Invalid password')
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect password", headers={'WWW-Authenticate': 'Basic'})
        if new_hash and self.new_hash is not None:
            self.new_hash(new_hash)
            self.logger.info('New hash generated and saved')


#####
# JSON Storage webservices
#####

def datetime_todb(d: datetime.datetime) -> str:
    return d.isoformat(sep=' ', timespec='seconds')

def datetime_fromdb(s: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(s)

STATUS_DESCR = {
    status.HTTP_204_NO_CONTENT: { 'description': 'Sucessfully removed' },
    status.HTTP_403_FORBIDDEN: { 'description': 'Authorization failed' },
    status.HTTP_404_NOT_FOUND: { 'description': 'Requested resource not found' },
    status.HTTP_501_NOT_IMPLEMENTED: { 'description': 'This function is not implemented. (PATCH required the jsonpatch module)' }
}
RESPONSE_JSON = {
    'description': 'The stored json object',
    'content': {
        'application/json': {
            'example': { "key": "value", "...": "..." }
        }
    }
}

def responses(*args):
    return {k:STATUS_DESCR[k] for k in STATUS_DESCR if k in args}

class TrueString(str):
    """String where an empty string is still truthy."""
    def __bool__(self):
        return True

class JSONStorage:
    """JSON storage webservices"""
    sql_get_item = "select s.content from storage s where s.name = :p and effdt <= :d and not exists (select 1 from storage where name = s.name and effdt > s.effdt and effdt <= :d) and s.status = 'A'"
    sql_insert_item = "insert into storage values(:p, :d, :s, :c)"

    def __init__(self, base_dir: Path, config: Config, logger: 'loguru._logger.Logger'):
        self.config = config
        self.logger = logger
        self._db_file = base_dir / config.get('database.filename', 'jsonstorage.sqlite')
        if not self._db_file.exists():
            self.logger.debug('New database file {}', self._db_file)
            self._db_init()

    def get_list(self,
        like: str = Query(None, description="Filter with sql 'like' syntax", example='%abc%'),
        glob: str = Query(None, description="Filter with 'glob' syntax", example='\*abc\*'),
        sync: bool = Query(False, description="Output sync format with update date/time"),
        cleanup: bool = Query(False, description="Do cleanup of database first")
    ):
        """List stored json objects"""
        criteria = []
        if like is not None:
            criteria.append("s.name like :l")
        if glob is not None:
            criteria.append("s.name glob :g")
        crit = ""
        if criteria:
            crit = "and {}".format(" and ".join(criteria))

        with self._db_connect() as conn:
            cur = conn.cursor()
            if cleanup:
                self.logger.info('Cleanup: removing old inactive items from the database')
                cur.execute("with old_stuff as (select s.name, s.effdt from storage s where s.effdt < datetime('now', '-1 years') {} and (s.status = 'I' or exists (select 1 from storage where name = s.name and effdt > s.effdt))) delete from storage where exists (select 1 from old_stuff where name = storage.name and effdt = storage.effdt)".format(crit))

            if sync:
                self.logger.debug('Sync list for items like {} or {}', like, glob)
                cur.execute("select s.name, s.effdt, s.status from storage s where 1=1 {} order by s.name, s.effdt".format(crit), {'l': like, 'g': glob})
                items = [{ 'name': row['name'], 'effdt': datetime_fromdb(row['effdt']), 'status': row['status']} for row in cur.fetchall()]
            else:
                self.logger.debug('List for items like {} or {}', like, glob)
                cur.execute("select s.name from storage s where effdt <= :d and not exists (select 1 from storage where name = s.name and effdt > s.effdt and effdt <= :d) and s.status = 'A' {} order by s.name".format(crit), {'l': like, 'g': glob, 'd': datetime_todb(datetime.datetime.utcnow())})
                items = [row['name'] for row in cur.fetchall()]
            cur.close()

        return items
    get_list.route = '/'
    get_list.route_params = {
        'responses': {
                status.HTTP_200_OK: {
                    'description': 'List of json object ids',
                    'content': {
                        'application/json': {
                            'example': [ 'id', '...' ]
                        }
                    }
                }
            },
        'name': 'storage.list',
        'summary': 'List available json objects',
        'description': TrueString()
    }

    def get_json(self,
        id: str,
        effdt: datetime.datetime = Query(None, description="Get item with specific date/time"),
    ):
        """Retrieve a stored json object"""
        self.logger.debug('Get item {}', id)
        if effdt is None:
            effdt = datetime.datetime.utcnow()

        with self._db_connect() as conn:
            cur = conn.cursor()
            cur.execute(self.sql_get_item, {'p': id, 'd': datetime_todb(effdt)})
            row = cur.fetchone()
            cur.close()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return json.loads(row['content'])
    get_json.route = '/{id:path}'
    get_json.route_params = {
        'responses': {
            status.HTTP_200_OK: RESPONSE_JSON,
            **responses(status.HTTP_404_NOT_FOUND)
        },
        'name': 'storage.get',
        'summary': 'Retrieve a json object',
        'description': TrueString(),
        'response_description': 'The stored json object'
    }

    def post_json(self,
        content = Body(..., example={ "key": "value", "...": "..." }),
        effdt: datetime.datetime = Query(None, description='Add item with specific date/time'),
        prefix: str = Query('', description='Add prefix to the generated id')
    ):
        """Store a json object with a new id"""
        self.logger.debug('Post: new item id')
        id = '{}{}'.format(prefix, uuid.uuid1())
        return {
            'id': id,
            'content': self.put_json(id, content=content, effdt=effdt)
        }
    post_json.route = '/'
    post_json.route_params = {
        'status_code': status.HTTP_201_CREATED,
        'responses': {
            status.HTTP_201_CREATED: {
                'description': 'An id and the stored json object',
                'content': {
                    'application/json': {
                        'example': { "id": "new id", "content": RESPONSE_JSON['content']['application/json']['example'] }
                    }
                }
            },
            **responses(status.HTTP_404_NOT_FOUND)
        },
        'name': 'storage.post',
        'summary': 'Store a json object',
        'description': TrueString(),
        'response_description': 'The stored json object'
    }

    def put_json(self,
        id: str,
        content = Body(..., example={ "key": "value", "...": "..." }),
        effdt: datetime.datetime = Query(None, description="Add item with specific date/time"),
    ):
        """Store a json object"""
        self.logger.debug('Put item {}', id)
        if effdt is None:
            effdt = datetime.datetime.utcnow()

        with self._db_connect() as conn:
            cur = conn.cursor()
            cur.execute(self.sql_insert_item, {'p': id, 'd': datetime_todb(effdt), 's': 'A', 'c': json.dumps(content)})
            cur.close()
        return content
    put_json.route = '/{id:path}'
    put_json.route_params = {
        'status_code': status.HTTP_201_CREATED,
        'responses': {
            status.HTTP_201_CREATED: RESPONSE_JSON,
            **responses(status.HTTP_404_NOT_FOUND)
        },
        'name': 'storage.put',
        'summary': 'Store a json object',
        'description': TrueString(),
        'response_description': 'The stored json object'
    }

    def patch_json(self,
        id: str,
        patch = Body(..., media_type='application/json-patch+json', example=[ { "op": "...", "path": "...", "value": "..."}, "..." ])
    ):
        """Change a stored json object"""
        # Depends on having the jsonpatch module
        if jsonpatch is None:
            HTTPException(status.HTTP_501_NOT_IMPLEMENTED)

        self.logger.debug('Patch item {}', id)
        with self._db_connect() as conn:
            cur = conn.cursor()
            cur.execute(self.sql_get_item, {'p': id, 'd': datetime_todb(datetime.datetime.utcnow())})
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            json_orig = json.loads(row['content'])
            json_new = jsonpatch.apply_patch(json_orig, patch)

            cur.execute(self.sql_insert_item, {'p': id, 'd': datetime_todb(datetime.datetime.utcnow()), 's': 'A', 'c': json.dumps(json_new)})
            cur.close()

        return json_new
    patch_json.route = '/{id:path}'
    patch_json.route_params = {
        'responses': {
            status.HTTP_200_OK: RESPONSE_JSON,
            **responses(status.HTTP_404_NOT_FOUND, status.HTTP_501_NOT_IMPLEMENTED)
        },
        'name': 'storage.patch',
        'summary': 'Change a stored json object',
        'description': 'For json patch syntax, see [http://jsonpatch.com/](http://jsonpatch.com/).',
        'response_description': 'The stored json object'
    }

    def delete_json(self,
        id: str,
        effdt: datetime.datetime = Query(None, description="Delete item with specific date/time"),
    ):
        """Remove a stored json object"""
        self.logger.debug('Delete item {}', id)
        if effdt is None:
            effdt = datetime.datetime.utcnow()

        with self._db_connect() as conn:
            cur = conn.cursor()

            cur.execute(self.sql_get_item, {'p': id, 'd': datetime_todb(effdt)})
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            cur.execute(self.sql_insert_item, {'p': id, 'd': datetime_todb(effdt), 's': 'I', 'c': ''})
            cur.close()
        # default satus 204 when deleting something, 404 when there was nothing to delete
    delete_json.route = '/{id:path}'
    delete_json.route_params = {
        'response_class': Response,
        'responses': responses(status.HTTP_204_NO_CONTENT, status.HTTP_404_NOT_FOUND),
        'status_code': status.HTTP_204_NO_CONTENT,
        'name': 'storage.delete',
        'summary': 'Remove a stored json object',
        'description': 'The stored object is not really deleted, but marked as invalid. This way history is preserved.'
    }

    def router(self):
        """Create routings from methods"""
        # .route = '...'        - FastAPI route
        # .route_params = {}    - other route parameters (kwargs)
        # .httpmethod = '...'   - (optional) http method (GET, POST, PUT, PATCH, DELETE, HEAD)
        #                         otherwize, use the first part of the name (up until the first _)
        handlers = []
        for name in dir(self):
            # quickly skip special methods
            if name.startswith('_'):
                continue

            handler = getattr(self, name)
            if not hasattr(handler, 'route'):
                continue

            try:
                http_method = handler.http_method
            except AttributeError:
                http_method = name.split('_', 1)[0]

            handlers.append((handler.route, http_method.lower(), handler))
        # sort by route, so parameters '{...}' will follow fixed routes
        handlers.sort()

        router = APIRouter()
        for (route, http_method, handler) in handlers:
            # equivalent to
            #   @router.get(route, **route_params)
            #   def handler(...):
            add = getattr(router, http_method)
            add(route, **getattr(handler, 'route_params', {}))(handler)
        return router

    @contextlib.contextmanager
    def _db_connect(self) -> sqlite3.Connection:
        """Connect to the sqlite3 database"""
        conn = sqlite3.connect(self._db_file)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except:
            # re-raise exceptions
            raise
        else:
            # no exceptions
            conn.commit()
        finally:
            # always
            conn.close()

    def _db_init(self):
        """Initialize the database"""
        with self._db_connect() as conn:
            conn.executescript("""
            create table storage (name text, effdt datetime, status text, content text);
            create unique index idx_storage on storage (name, effdt);
            """)


#####
# The main program
#####
def save_new_hash(cfg: Config):
    """Save new hash to config file"""
    def callback(new_hash):
        cfg.set('security.hash', new_hash)
        cfg.save()
    return callback

def main(args=None):
    if args is None:
        args = sys.argv[1:]
    if len(args) < 1:
        args.append('.')

    # Config
    config = Config(Path(args[0]))

    base_dir = Path(config.get('server.directory', config.path.parent)).expanduser()

    # Logging
    logger.configure(
        handlers = [],
        extra = { 'logtype': 'main' }
    )

    # console logging
    loglevel = config.get('logging.console level', 'error').upper()
    if loglevel != 'DISABLE':
        loglevel = logger.level(loglevel)
        debug = (loglevel.no <= logger.level('DEBUG').no)
        levelstr = '{level.icon: ^3}' if sys.stderr.encoding == 'utf-8' else '{level: <8}'
        logger.add(sys.stderr,
            level = loglevel.name,
            format = '<light-black>{time:YYYY-MM-DD HH:mm:ss}</light-black> | <level>' + levelstr + '</level> | {extra[logtype]} | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - {message}',
            filter = None,
            backtrace = debug,
            diagnose = debug
        )

    # file logging
    loglevel = config.get('logging.file level', 'error').upper()
    if loglevel != 'DISABLE':
        loglevel = logger.level(loglevel)
        debug = (loglevel.no <= logger.level('DEBUG').no)
        logdir = Path(config.get('logging.directory', base_dir)).expanduser().resolve()
        logger.add(logdir / 'app-{time:YYYY-MM-DD}.log',
            level = loglevel.name,
            format = '{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {extra[logtype]} | {name}:{function}:{line} - {message}',
            filter = None,
            backtrace = debug,
            diagnose = debug,
            enqueue = True,
            encoding = 'utf-8',
            rotation = '00:00',
            retention = 5,
            compression = None if debug else 'zip'
        )

    # Authentication
    sec_logger = logger.bind(logtype='main.security')
    pwd = config.get('security.password')
    if pwd is not None:
        config['security.hash'] = Security.context.hash(pwd)
        del config['security.password']
        config.save()
        sec_logger.info('New password hashed and saved')
    pwd_hash = config.get('security.hash')
    if pwd_hash is None:
        pwd = getpass.getpass()
        pwd_hash = Security.context.hash(pwd)
        config['security.hash'] = pwd_hash
        config.save()
        sec_logger.info('New password hashed and saved')
    del pwd

    security = Security(config['security.hash'], period=config.get('security.period', 0), new_hash=save_new_hash(config), logger=sec_logger)

    # JSON Storage
    jsonstore = JSONStorage(base_dir, config, logger)

    app = FastAPI(
        title = 'JSON Storage',
        dependencies = [Depends(security.valid_password)],
        docs_url = '/docs',
        redoc_url = None
    )
    app.include_router(
        jsonstore.router(),
        responses = responses(status.HTTP_403_FORBIDDEN)
    )

    # Run server
    ssl_keyfile = config.get('server.ssl-key')
    if ssl_keyfile is not None:
        ssl_keyfile = base_dir / ssl_keyfile
    ssl_certfile = config.get('server.ssl-cert')
    if ssl_certfile is not None:
        ssl_certfile = base_dir / ssl_certfile

    uvicorn.run(
        app,
        host = config.get('server.host', 'localhost'),
        port = config.get('server.port', 8001),
        log_config = dict(version=1, disable_existing_loggers=False),
        log_level = 'debug', # log everything, then let loguru handle the filtering
        ssl_keyfile = ssl_keyfile,
        ssl_certfile = ssl_certfile
    )

    return 0

if __name__ == '__main__':
    sys.exit(main())
