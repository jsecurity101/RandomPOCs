# RandomPOCs
This repository holds POCs I have created for projects, blogs, etc. 



## POCs: 


| POC | Description | 
| --- | ---- |
| ImpersonateLoggedOnUser | Steals token from a targetted process and sets token to current thread via ImpersonateLoggedOnUser | 
| SetThreadToken | Steals token from a targetted process and sets token to current thread via SetThreadToken |
| NtfsControlFile | Performs named pipe impersonation by creating a named pipe - `\\.\pipe\npfs` and taking the clients token by calling NtfsControlFile|
