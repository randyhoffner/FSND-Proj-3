# FSND Multi-User Blog Project

## Overview
This project is a multi-user blog which can be expanded to contain multiple multi-user blogs.  It was developed using Python 2.7, Google Cloud Appengine, and Jinja2.

## Repository Contents
The git repository contains the files required to run the project.  Download or clone the project.  Running the project requires Python 2.7 and the Google Cloud SDK to be installed on your machine.  To run the project locally, use a command line: Mac Terminal or the Windows Google Cloud SDK Shell.  Navigate to the project folder, and run dev_appserver.py .  This will permit you to navigate a browser to localhost:8080 which will open the main page.

## Using the App
When the localhost page is opened locally, the main page is displayed, which instructs you to add /blog to the localhost URL, which will open the blog front page.  Alternatively, navigate initially to localhost:8080/blog to go directly to the blog front page. You can then signup and start posting.  Making a new post, and most other actions, require you to click on the "Randy's Blog" title, which will render the refreshed front page.

The project may be run online by navigating to [https://randysblog-154601.appspot.com/blog](https://randysblog-154601.appspot.com/blog).

Commands for navigating the blog:

* To refresh the front page, click on the "Randy's Blog" title at the top of the page.
* To go to a post's permalink page, click on the (red) post's title.
* On the front page, click on "signup", enter a username, a password, and optionally an email.  You may then "logout" and "login".
* To make a post, click on "New Post".
* Add or edit a comment by clicking on (add new comment) or (edit comment) respectively.  You may edit only your own posts.
* To Like a post, click on "Like".  You may not like your own posts, and you may only like a post once.
* To edit or delete a post, click on "Edit" or "Delete".  You may only edit or delete your own posts.
