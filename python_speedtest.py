#This file is a test file to prove that print is slowing down everything

def test1():
    numlist = []
    for num in range(1, 10000):
        numlist.append(num)
        print(num)
    print("done")
    exit()

def test2():
    numlist = []
    for num in range(1, 10000):
        numlist.append(num)
    print("done")
    exit()


test2()
