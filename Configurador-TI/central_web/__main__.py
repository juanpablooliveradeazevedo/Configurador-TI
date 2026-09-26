import argparse
from fleet_protocol.transport import Transport
from .server import CentralServer

def main():
    p=argparse.ArgumentParser(description='Configurador TI Central Web LOCAL QA ONLY')
    p.add_argument('--backend',default='http://127.0.0.1:8765');p.add_argument('--port',type=int,default=8766);p.add_argument('--qa',action='store_true',required=True)
    a=p.parse_args()
    with CentralServer(('127.0.0.1',a.port),Transport(a.backend,qa=a.qa)) as s: s.serve_forever()
if __name__=='__main__': main()
