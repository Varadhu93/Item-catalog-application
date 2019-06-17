># Item Catalog Project

>## About the Project

You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

>## Why This Project?

Modern web applications perform a variety of functions and provide amazing features and utilities to their users; but deep down, it’s really all just creating, reading, updating and deleting data. In this project, you’ll combine your knowledge of building dynamic websites with persistent data storage to create a web application that provides a compelling service to your users.

>## What Will I Learn?

You will learn how to develop a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication. You will then learn when to properly use the various HTTP methods available to you and how these methods relate to CRUD (create, read, update and delete) operations.

>### Pre-requisites

* [Python2 or Python3](https://www.python.org/)
* [vagrant](https://www.vagrantup.com/)
* [VirtualBox](https://www.virtualbox.org/)
* [Bootstrap] (https://getbootstrap.com/docs/4.3/getting-started/introduction/)
* [Jinja2] (http://jinja.pocoo.org/)

>### Tech Stack

* Python
* HTML
* CSS
* OAuth
* Flask
* Jinja2

>### Requirements

* Clone the fullstack-nanodegree-vm
* Launch the Vagrant VM (vagrant up)
* Install Vagrant and VirtualBox

>### Bringing the VM up

Bring up the VM with the following command:
`vagrant up`

The first time you run this command, it will take awhile, as Vagrant needs to download the VM image.

You can then log into the VM with the following command:
`vagrant ssh`

Once inside the VM, navigate to the tournament directory with this command:
`cd /vagrant`

* Write your Flask application locally in the vagrant/catalog directory (which will automatically be synced to /vagrant/catalog within the VM).

>## Running the application

* Run your application within the VM (python /vagrant/catalog/application.py)
`$ python application.py`
* Access and test your application by visiting http://localhost:8000 or http://localhost:8000/catalog
* static - css, js files etc
* templates - path to html files

>### Shutting the VM down

When you are finished with the VM, press Ctrl-D to log out of it and shut it down with this command:

`vagrant halt`
