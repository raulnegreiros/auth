#!/usr/bin/python
#  this is a utility script
# this script check a list of dependencies, like if databases is ready.
#  When all dependencies are fulfilled, the script ends

from CollectionManager import CollectionManager
import sys
import json
from time import sleep

poolingsec = 5

def waitMongo(configuration):
    print 'Waiting for mongo...'
    while (True):
        try:
            collection = CollectionManager(configuration['database']).getCollection(configuration['collection'])
            if collection is not None:
                x = collection.find_one()
                break
        except KeyError as e:
            print 'Malformed configuration at dependence->mongo->' + str(e.message) + ' aborting.'
            exit(-1)
        except: #pymongo erros
            collection = None
        
        print 'mongo fail..will try again in ' + str(poolingsec)
        sleep(poolingsec)
    print 'Mongo is ready'

def verifyDependences():
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--sleep':
            global poolingsec
            poolingsec = int(sys.argv[i+1])
            i = i + 1
        
        elif sys.argv[i] == '--mongo':
            configuration = json.loads(sys.argv[i+1])
            waitMongo(configuration)
            i = i + 1

        #we could add more dependences types here
        #elif sys.argv[i] == ?
        i = i + 1

if __name__ == '__main__':
    verifyDependences()
    print 'all dependences fulfilled. Exiting'
    exit(0)