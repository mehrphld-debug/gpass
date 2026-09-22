i need random password generator in my terminal (mac os, linux) in python or rust.

the structure must be :

user type : keyword (app name) -switch1 -switch2  -switch3

-switch1 is the length of the genrated txt in number (deafult is 13)

-switch2 is the charachter set  (
 1 : lowercase chars ,2: uppercase chars ,3: numbers ,4: special chars
)
	if -switch2 was the one of them like 1 or 4, generate only the exact config,
	for multiple char sets, numbers be like (13) means only lowercase chars + numbers or 1234 means generate with all chars.

-switch3 says save the password or not ? if -y : save at '~/Documents/psess.txt', in {key: value} pair which key is the name and value is the password. everytime it must append the new {key: value} to the file and not over-write previouse values. if user dosnt input the -switch3 dont save or write it anywhere, only show it to the terminal once.

flag -y at -switch3 also needs another input may input as -switch4 if user dosnt input -switch4 ask the name for pass.

-switch4 is the name of the generated pass. (optional)

final command is like this : pypass -12 -134 -y -keyOne OR pypass -12 -123 -y 
	means : generate random password in 12 charachters in combination of  lowercase chars + numbers + speacial chars

the main structure can be apply at both rust and python. it must install as an application, not running every time as a script.
security is very important. i need a safe and secure app + unique and safe random passwords. i need a lightweight program to run fast and efficcent. every time that app calls from the user, it must do its job and close every sources that has been used. it must be open to add new features for more work and outputs in the future. this stage focous only on the main job => generate unique and custom passwords in terminal that can be one time or append to the password files. all passwords must be unique.
before any build, compare this tool with both python and rust architecture. the winner is the main language and framework for building this tool. 