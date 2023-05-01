# About Me
This is my own kind of python cipher program, with argparse and an interactive CLI<br>
Made by: @NewGuy103

# Usage
	pycrypter.py -h -> Prints the help message <br>
	Non-interactive arguments:
	
	==[Required Arguments]==
	e/--encrypt -> Sets the cipher method to "encrypt"
	d/--decrypt -> Sets the cipher method to "decrypt"

	--[Can be omitted, as long as one is present]--
	--file and --directory require an input argument, --ransomware can be used without input arguments.
	
	-f/--file input_file -> The file passed to cipher.
	-dr/--directory input_dir -> The directory passed to cipher. [Cipher the files inside the directory]

	-rw/--ransomware -> This will fetch the current user's User folder [C:\\Users\\{current_user}] and cipher it.
	  [I'm not liable if you use this maliciously, you ran it]

	==[Optional Arguments]==
	--threads takes in an integer as an optional argument.

	-ds/--deep-search -> Search the sub-directories of the directory passed in -dr.
	  [This will do nothing if you used -f/--file]
	-c/--keep-copy -> Keep a copy of the ciphered file. 

	-v/--verbose -> Show more detailed outputs to the output stream.
	-t/--threads -> Set the amount of threads that can cipher files. 
	
	Interactive commands:
	
	[Cipher commands]
	encrypt -f/--file <input file> -dr/--directory <input directory> [-c/--keep-copy] [-rw/--ransomware]
	decrypt -f/--file <input file> -dr/--directory <input directory> [-c/--keep-copy] [-rw/--ransomware]
	
	[Deletion commands]
	safedel input_file [-fd/--fdel]

# Documentation
