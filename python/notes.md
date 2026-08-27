# note-commands
Cheet-sheet commands will be displayed under each related topic

----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------


Python debugger 
https://thonny.org/


----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------


Installation of Python in your home directory in linux (without sudo rights)

HOW TO INSTALL:
# Optional:
# which python 
# deactivate

Install Python3.9
1. wget http://www.python.org/ftp/python/3.9.7/Python-3.9.7.tgz
2. tar -zxvf Python-3.9.7.tgz
3. cd Python-3.9.7
4. makdir ~/.localpython
5. ./configure --prefix=/home/USERNAME/.localpython (check USERNAME run: whoami)
6. make
7. make install

Install VirtualEnv (compatible with python3.9)
1. ~/.localpython/bin/python3.9 -m pip install yirtualeny
2. ~/.localpython/bin/virtualeny ~/myenv

Activate and check Python3.g
1. source ~/myenv/bin/activate
2. which python
3. python3 --version