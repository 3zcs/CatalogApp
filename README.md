## Instlation 
You should have python and SQLAlchemy On your machine.<br />
Fork this repo using terminal <br />
`$ git clone https://github.com/3zcs/CatalogApp.git`<br />
Then enter your folder <br />
`$ cd catalog`<br />
Install any module if needed with this command `pip install module-name`<br />

## Run project 
in terminal run vagrant `$ vagrant up` then login in the virtual machine using secure shell "SSH" `$ vagrant ssh`<br />
Run this command in terminal to create database file and the `category.db` will be shown in the folder `$ python database_setup.py`<br />
Run this command in terminal to run the server `$ python catalog_app.py`<br />
Go to `localhost:5000` index page of this project <br />

## project structure
**category.db** Database file of this project <br />
**database_setup.py** Create database file and manage orm <br />
**catalog_app.py** Run server and manage all route request and respnse <br />
**static folder** All CSS and javascript file <br />
**templates** Contain all html file for all pages  <br />

## Note 
Make sute to use `localhost:5000` instead of `0.0.0.0:5000` beacuse google sign in won't work with you <br />
