# JSON Storage

A webservice to store and retrieve JSON data.

Uses FastAPI/uvicorn for the server and sqlite3 as the database.

It is a stand-alone part of a larger project for a locally run server as an
interface (through html) to some of my scripts. As such, it is meant as a
single-user service and only uses a password (via http basic authentication)
for authentication.

## Configuration

The first (and only) argument is the path to a configuration file. If omitted
(or a directory), it uses `config.json`.

Any file paths in the configuration file are relative to the instance directory
which is in the configuration file or, when omitted, the directory
containing the configuration file.

If you include a password entry in the security section, it will be hashed and
stored like that in the configuration file on the next startup.
If both password and hash are omitted, the app will ask for a new password on
startup.

## Webservices

The app uses FastAPI for the webservices. The API is available on the server
as `/docs`.

## Use in javascript

Without access to the filesystem, html/javascript pages can use it to store
information:

```javascript
// Store
fetch('https://localhost:8001/test', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
	.then(response => {
		if (!response.ok) { throw new Error(`Storage failed: ${response.status} - ${response.statusText}`); }
	})
	.catch(error => { console.log(error); });

// Retrieve
fetch('https://localhost:8001/test')
	.then(response => {
		if (!response.ok) { throw new Error(`Storage failed: ${response.status} - ${response.statusText}`); }
		return response.json()
	})
	.then(data => {
		// Do something with the data
	})
	.catch(error => { console.log(error); });
```
