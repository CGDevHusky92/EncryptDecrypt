EncryptDecrypt
==============

A simple encryption/decryption program. Initial attempt at securing a program needs updating.

I chose "SuCc" as my KID and it stands for Successful encryption.
I chose "eNcR" as my MAGIC number which stands for encryption.

As far as security related decisions went, I decided to error check every possible function
and release any memory that was allocated if there was any sort of failures. I check every 
input including argv. I even check argc for any sort of overflow. When opening the file, I
make sure not to follow any symbolic links and check permissions. I also decided to lock the 
memory that stores the passwords, being entered.

The length is in fact revealed by two key factors. First off is the start offset for the 
unclassified content and second is the number of X's in the unclassified content. Using these
two pieces of information we can add up the bytes being used by sN and lN along with N. We can
then calculate the size of the ecrypted kid and key file. You could conceal the length by 
dispersing the encrypted content across the file and parsing it out and putting it back 
together later.

The file can be read on any architecture, but the bytes may be out of order due to endianness. 
This would have to be taken into account for when writing software to parse and decrypt the files.


ToDo
====
Update security related code.
Update for Mac OS X.


Considerations:
===============
As always have fun use at your own risk and don't blame me if things don't work. This is just a side project for learning.
If you actually need help with anything feel free to contact me and I'll gladly try to help. I am sublicensing this under
an MIT license, so go out use it and have fun.