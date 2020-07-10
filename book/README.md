# Book
## 1- Overview

[![card](images/card.png "Book")](https://www.hackthebox.eu/home/machines/profile/230)   

Retire: 11 July 2020   
Writeup: 11 July 2020



### Summary

**2- [Enumeration](https://github.com/flast101/HTB-writeups/tree/mastSer/book#2--enumeration)**   
2.1- [nmap scan](https://github.com/flast101/HTB-writeups/tree/master/book#21--nmap-scan)   
2.2- 

**3- [Exploitation](https://github.com/flast101/HTB-writeups/tree/master/book#44--exploitation)**   

**4- [Privilege Escalation](https://github.com/flast101/HTB-writeups/tree/master/book#4--privilege-escalation)**   
4.1- [Post-Compromise Enumeration](https://github.com/flast101/HTB-writeups/tree/master/book#41--post-compromise-enumeration)        
4.2- [Post-Compromise Exploitation](https://github.com/flast101/HTB-book/tree/master/servmon#42--post-compromise-exploitation)       


## 2- Enumeration
### 2.1- nmap scan

First things first, we begin with a `nmap` scan:
~~~
root@kali:~# nmap --reason -Pn -sV -sC --version-all 10.10.10.176


~~~

