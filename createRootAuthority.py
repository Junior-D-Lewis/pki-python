import os

def createRootAuthority():
    createRootCA()

def createRootCA():
    os.mkdir("test")
    os.chdir("/root/ca")
    os.mkdir("c")