## Learnings

* After enumeration, be sure to check each and every port on a browser (which are not identified by nmap especially )
* CMS Version of a website can be checked by inspecting the following: ``<meta name="generator" content="WordPress 6.3.1" />``
* Check each and every feature of a website, do not miss a single one, however tedious it may be. Anything can provide an attack surface
* You can upload and execute zip files too, if php files cannot be uploaded.
* It is not uncommon for admins to reuse passwords.
* Keep in mind both `sudo su` and `sudo root`  for switching to the root user