How to use
----------

* Install requirements: pip install -r requirements.txt

* Import KeepassReader.py in your project

* Create a KeepassReader object : reader = KeepassReader()

* Fetch the XML with the (*.kdbx) database and the password : xml = reader.open("filename.kdbx", "password here")

* Fetch the entries with the XML : entries = reader.parse(xml)

Errors and problems
-------------------

If you have any problem, check the error status : reader.status['error']

* 0 = No error
* 1 = Database corrupted or invalid password
* 2 = Cannot open the database (*.kdbx)
* 3 = No XML provided to the parse method
