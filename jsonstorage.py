#!/usr/bin/env python3
# encoding: UTF-8

"""JSON storage webservice

Provides REST webservices (with FastAPI) to store and retrieve json objects.
"""

__author__  = 'Rogier Steehouder'
__date__    = '2021-12-11'
__version__ = '1.0'

import sys
import contextlib
import datetime
import getpass
import json
import sqlite3
from pathlib import Path
from typing import List

import uvicorn
from fastapi import FastAPI, Depends, APIRouter, Query, Body, Response, status, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
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


#####
# Configuration
#####
class Config:
    """Config class

    Can read/save json or yaml.
    Use dot notation to get subkeys.
    """
    def __init__(self, filename):
        self.path = Path(filename)
        self.load()

    @property
    def path(self):
        return self._path
    @path.setter
    def path(self, p):
        self._path = Path(p)
        self.yaml = (yaml and self._path.suffix == '.yaml')

    def load(self):
        """Load config from file"""
        if self.yaml:
            self._config = yaml.load(self.path.read_text())
        else:
            self._config = json.loads(self.path.read_text())

    def save(self):
        """Save config to file"""
        if self.yaml:
            yaml.dump(self._config, self.path)
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
    def __init__(self, hash: str, *, period: int = 0, new_hash: callable = None):
        self.hash = hash
        self.new_hash = new_hash

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
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect password", headers={'WWW-Authenticate': 'Basic'})
        if new_hash and self.new_hash is not None:
            self.new_hash(new_hash)


#####
# JSON Storage webservices
#####

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
    def __init__(self, base_dir: Path, config: Config):
        self.config = config
        self._db_file = base_dir / config.get('database.filename', 'jsonstorage.sqlite')
        if not self._db_file.exists():
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
                cur.execute("with old_stuff as (select s.name, s.effdt from storage s where s.effdt < datetime('now', '-1 years') {} and (s.status = 'I' or exists (select 1 from storage where name = s.name and effdt > s.effdt))) delete from storage where exists (select 1 from old_stuff where name = storage.name and effdt = storage.effdt)".format(crit))

            if sync:
                cur.execute("select s.name, s.effdt, s.status from storage s order by s.name, s.effdt".format(crit), {'l': like, 'g': glob})
                items = [{ 'name': row['name'], 'effdt': datetime.datetime.fromisoformat(row['effdt']), 'status': row['status']} for row in cur.fetchall()]
            else:
                cur.execute("select s.name from storage s where not exists (select 1 from storage where name = s.name and effdt > s.effdt) and s.status = 'A' {} order by s.name".format(crit), {'l': like, 'g': glob})
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
        id: str
    ):
        """Retrieve a stored json object"""
        with self._db_connect() as conn:
            cur = conn.cursor()
            cur.execute("select s.content from storage s where s.name = :p and not exists (select 1 from storage where name = s.name and effdt > s.effdt) and s.status = 'A'", {'p': id})
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

    def put_json(self,
        id: str,
        content = Body(..., example={ "key": "value", "...": "..." })
    ):
        """Store a json object"""
        with self._db_connect() as conn:
            cur = conn.cursor()
            cur.execute("insert into storage values(:p, CURRENT_TIMESTAMP, 'A', :c)", {'p': id, 'c': json.dumps(content)})
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

        with self._db_connect() as conn:
            cur = conn.cursor()
            cur.execute("select s.content from storage s where s.name = :p and not exists (select 1 from storage where name = s.name and effdt > s.effdt) and s.status = 'A'", {'p': id})
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            json_orig = json.loads(row['content'])
            json_new = jsonpatch.apply_patch(json_orig, patch)

            cur.execute("insert into storage values(:p, CURRENT_TIMESTAMP, 'A', :c)", {'p': id, 'c': json.dumps(json_new)})
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
        id: str
    ):
        """Remove a stored json object"""
        found = 0
        with self._db_connect() as conn:
            cur = conn.cursor()

            cur.execute("select 1 from storage s where s.name = :p and not exists (select 1 from storage where name = s.name and effdt > s.effdt) and s.status = 'A'", {'p': id})
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND)

            #cur.execute("delete from storage where name = :p", {'p': id})
            cur.execute("insert into storage values(:p, CURRENT_TIMESTAMP, 'I', '')", {'p': id})
            cur.close()
        # default satus 204 when deleting something, 404 when there was nothing to delete
    delete_json.route = '/{id:path}'
    delete_json.route_params = {
        'response_class': Response,
        'responses': responses(status.HTTP_204_NO_CONTENT, status.HTTP_404_NOT_FOUND),
        'status_code': status.HTTP_204_NO_CONTENT,
        'name': 'storage.delete',
        'summary': 'Remove a stored json object',
        'description': TrueString()
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
    cfg_file = Path(args[0])
    if cfg_file.is_dir():
        cfg_file = cfg_file / 'config.json'
    cfg = Config(cfg_file)

    base_dir = Path(cfg.get('server.directory', cfg_file.parent)).expanduser()

    # Password
    pwd = cfg.get('security.password')
    if pwd is not None:
        cfg['security.hash'] = Security.context.hash(pwd)
        del cfg['security.password']
        cfg.save()
    pwd_hash = cfg.get('security.hash')
    if pwd_hash is None:
        pwd = getpass.getpass()
        pwd_hash = Security.context.hash(pwd)
        cfg['security.hash'] = pwd_hash
        cfg.save()
    del pwd

    security = Security(cfg['security.hash'], period=cfg.get('security.period', 0), new_hash=save_new_hash(cfg))

    # JSON Storage
    jsonstore = JSONStorage(base_dir, cfg)

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
    ssl_keyfile = cfg.get('server.ssl-key')
    if ssl_keyfile is not None:
        ssl_keyfile = base_dir / ssl_keyfile
    ssl_certfile = cfg.get('server.ssl-cert')
    if ssl_certfile is not None:
        ssl_certfile = base_dir / ssl_certfile

    uvicorn.run(
        app,
        host = cfg.get('server.host', 'localhost'),
        port = cfg.get('server.port', 8001),
        log_level = cfg.get('server.log level', 'error'),
        ssl_keyfile = ssl_keyfile,
        ssl_certfile = ssl_certfile
    )

    return 0

if __name__ == '__main__':
    sys.exit(main())
