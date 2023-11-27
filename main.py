import requests as reqs
from kubernetes import client, config
import os
import sys
import time

#Globals, probably worth adding in some sort of direct failure here if these are not set
APIKEY = os.getenv("APIKEY")
ORGID = os.getenv("ORGID")
SNYKAPIVERSION = os.getenv("SNYKAPIVERSION")

#Scan any missing images, 'images' should be a iterable list
#We can modify the arguments of Snyk Container to include tags which can then be used to create project views or import metadata from the pods if needed
#Tags seem like an easy way to say 'this is monitored on your cluster / through this script'
def scanMissingImages(images):
    splitKey = APIKEY.split()

    #Auth the CLI
    cmd = '/usr/local/bin/snyk auth {}'.format(splitKey[1])
    os.system(cmd)
    
    for missingImage in images:

        #tag = missingImage.split(":")
        #tag = tag[1]
        modifiedImage = missingImage.replace(':', '_')
        
        #change out depending on what socket we can mount on the host
        print("Re-tagging {} to {}".format(missingImage, modifiedImage))
        cmd = 'docker tag {} {}'.format(missingImage, modifiedImage)
        #cmd = 'ctr images pull {}'.format(missingImage)
        os.system(cmd)
        #cmd = 'ctr --namespace=k8s.io images tag {} {}'.format(missingImage, modifiedImage)
        #cmd = 'ctr images tag {} {}:{}'.format(missingImage, modifiedImage, tag)
        #os.system(cmd)
        #projectName = missingImage.replace(":", "_")
        cmd = '/usr/local/bin/snyk container monitor {} --org={} --tags=kubernetes=monitored'.format(missingImage, ORGID)

        print("Scanning {}".format(modifiedImage))
        #cmd = '/usr/local/bin/snyk container monitor -d {} --org={} --tags=kubernetes=monitored '.format(modifiedImage, ORGID)
        os.system(cmd)


def deleteNonRunningTargets():

    #May be worth building in a retry mechanism instead of just failing
    try:
        containerImageURL = "https://api.snyk.io/rest/orgs/{}/container_images?version={}&limit=100".format(ORGID, SNYKAPIVERSION)
        containerResponse = reqs.get(containerImageURL, headers={'Authorization': '{}'.format(APIKEY)})
        containerResponseJSON = containerResponse.json()
        fullListofContainers = list(containerResponseJSON['data'])
        containerResponse.raise_for_status()
        while(containerResponseJSON.get('data') != None and 'Next' in containerResponseJSON['links'] ):
            containerResponse = reqs.get("https://api.snyk.io/{}&version={}".format(containerResponseJSON['links']['next'], SNYKAPIVERSION))
            containerResponseJSON = containerResponse.json()
            if containerResponseJSON.get('data') != None:
                fullListofContainers.append(containerResponseJSON['data'])

    except reqs.HTTPError as ex:
        print("ERROR: some error occured dumping target JSON {}".format(containerResponseJSON))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
        raise ex
    except reqs.Timeout:
        print("ERROR: Request to the container_images endpoint timed out, returning without completing")
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")

        raise ex


    #My cluster is small, the logic for this appears to be different from the above so idk if the while loop check works :(
    try:
        allTargetsUrl = "https://api.snyk.io/rest/orgs/{}/targets?version={}".format(ORGID, SNYKAPIVERSION)
        targetResponse = reqs.get(allTargetsUrl, headers={'Authorization': '{}'.format(APIKEY)})
        targetResponseJSON = targetResponse.json()
        targetResponse.raise_for_status()
        fullListofTargets = list(targetResponseJSON['data'])

        while(targetResponseJSON.get('data') != None and 'next' in targetResponseJSON['links'] ):
            targetResponse = reqs.get("https://api.snyk.io/rest/{}".format(targetResponseJSON['links']['next'], SNYKAPIVERSION), headers={'Authorization': '{}'.format(APIKEY)})
            targetResponseJSON = targetResponse.json()
            if targetResponseJSON.get('data') != None:
                fullListofTargets.append(targetResponseJSON['data'])

    except reqs.HTTPError as ex:
        print("ERROR: some error occured dumping target JSON {}".format(targetResponseJSON))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
        raise ex
    except reqs.Timeout:
        print("ERROR: Request to the Targets endpoint timed out, returning without completing")
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
        raise ex        


    replaceFunc = lambda x: x.replace(":", "_")
    allRunningPods_ = list(map(replaceFunc, allRunningPods))

    for containerImage in fullListofContainers:

        #image that is not running on the cluster
        #TODO: There is a scenario here where an image might not be listed in all running pods (when we replace : with _)
        #might have to put in place some logic to change the _ to : while doing the logic here. something like If imageName not in allrunningPods and imageName not in allRunningPods_

        for imageName in containerImage['attributes']['names']:

            imageTagStripped = imageName.split(':')
            imageTagStripped = imageTagStripped[0]
            if imageName not in allRunningPods and imageTagStripped not in allRunningPods_ and "@" not in imageName:

                #TODO: change the split to replace for '_', depending on the workflow it may make more sense to create targets with <image>_<version>
                #This really doesnt do much since it doesnt break it up in the UI. Long term itll be better to 'docker tag _' instead
                #If thats not the way we do it, possibly removing all this and deleting on the project level (and target if the target has no projects associated with it)
                #but that would require more logic and API calls. Mounting the docker socket might just be easier ¯\_(ツ)_/¯ 

                for target in targetResponseJSON['data']:
                    if target['attributes']['displayName'] == imageTagStripped:
                        deleteTargetURL = "https://api.snyk.io/rest/orgs/{}/targets/{}?version={}".format(ORGID,target['id'], SNYKAPIVERSION)
                        deleteResp = reqs.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                        if deleteResp.status_code == 204:
                            print("succesfully delete targetID {}, based off image {}".format(target['id'], imageTagStripped))
                        else:
                            print("Some issue deleting targetID {}, based off image {}. Response code: {}".format(target['id'], imageTagStripped, deleteResp.status_code))



#Load Kubeconfig for interacting with the K8s API. Load in K8s api V1 to query pods. 
if os.getenv('KUBERNETES_SERVICE_HOST'):
    print("KUBERNETES_SERVICE_HOST detected, atempting to load in pod config... ")
    config.load_incluster_config() 
else:
    print("KUBERNETES_SERVICE_HOST is not set, loading kubeconfig from localhost...")
    config.load_kube_config()
v1 = client.CoreV1Api()

#vars for later logic
allRunningPods = []
needsToBeScanned = []


for pod in v1.list_pod_for_all_namespaces().items:
    
    #TODO: change logic to use this, we can check the image and the ID. This works if no tag is defined.
    multiContainerPod = pod.status.container_statuses
    containerID = pod.status.container_statuses[0].image


    for container in pod.spec.containers: 
        image= container.image


        ##TODO: if the image we got is the image SHA, which contains @ instead of :, we wnat to cycle through our object (only multi container pod) to get the imageID
        #Which will be in the expected format. This happens when you deploy an image without a tag EG: doll1av/frontend instead of doll1av/frontend:latest
        #This also helps later where when using containerd you need the Fully qualified image name to actually tag images EG: docker.io/doll1av/frontend:latest
        if ':' not in image:
            for imagesInContainer in multiContainerPod:
                if image in imagesInContainer.image:
                    image = imagesInContainer.image


        allRunningPods.append(image)
        
        #will need to add some retry logic incase the connection dies
        URL = "https://api.snyk.io/rest/orgs/{}/container_images?names={}&version={}".format(ORGID, image, SNYKAPIVERSION)
        
        try:
            response = reqs.get(URL, headers={'Authorization': '{}'.format(APIKEY)})
            responseJSON = response.json()
        except reqs.HTTPError as ex:
            print("ERROR: Some error has occured, dumping response JSON: {}".format(responseJSON))
            print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            raise ex
        except reqs.Timeout:
            print("ERROR: Request to the container_images endpoint timed out for image {}".format(image))
            print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")

        #These are running on the API server but do not exist in Snyk
        #The None only works if the image has NEVER been scanned, after it has been scanned it we keep some data around
        #if responseJSON.get('data') == None:
        if responseJSON.get('data') == None or 'self' not in responseJSON['data'][0]['relationships']['image_target_refs']['links']:
           
            #Cant imagine customers want to be charged a license because they run this
            if 'a1doll/k8sreconciler' not in image:
                needsToBeScanned.append(image)




#Do the work we have set out to do
if len(needsToBeScanned) != 0:
    scanMissingImages(needsToBeScanned)
else:
    print("All images on the cluster are accounted for, skipping scanning function")

#If it seems like data isnt present when it should be, from Snyk, then consider adding a sleep here to compensate.
deleteNonRunningTargets()

#clean exit so our K8s job doesnt error out
sys.exit()