import json
from CollectionManager import CollectionManager
#this file contains the default configuration values
#and confiuration retrivement functions


#default configuration values.
defaultConfiguration = {
    'kongURL': 'http://kong:8001',
    'tokenExpiration': 420,
}

confCollection = CollectionManager('auth').getCollection('conf')


def getConfValue(confKey):
    configuration = confCollection.find_one()
    if configuration is None:
         loadconf()
         configuration = confCollection.find_one()
    
    if confKey in configuration.keys():
        return configuration[confKey]
    return None

def loadconf():
    configuration = confCollection.find_one()
    if configuration is None:
        print("No configuration found. Using default values")
        confCollection.insert_one(defaultConfiguration.copy())
    else:
        print('Configuration loaded')

        #validate if no field is mission on the configuration loaded
        dirty = False
        for key in defaultConfiguration:
            if key not in configuration.keys():
                print("Configuration for " + key + ' not found. Using default value: ' + defaultConfiguration[key])
                configuration[key] = defaultConfiguration[key]
                dirty = True
        
        #flag to update database only once
        if dirty:
            confCollection.replace_one({'_id': configuration['_id']}, configuration.copy())
 
