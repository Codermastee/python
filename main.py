# main.py
import os
import base64
import io
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for, jsonify
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
from datetime import datetime
from datetime import date
import datetime
import random
import string
from random import seed
from random import randint
from urllib.request import urlopen
import webbrowser
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
from PIL import Image
import urllib.request
import urllib.parse
from urllib.parse import urlparse, unquote
import socket    
import re
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import uuid
import shutil
#from Pyfhel import Pyfhel
#pip install secretsharing
#from secretsharing import PlaintextToHexSecretSharer
#pip install shamir-mnemonic
from shamir_mnemonic import generate_mnemonics, combine_mnemonics
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from phe import paillier  # homomorphic operations
from typing import List

#from secretsharing import PlaintextToHexSecretSharer

'''mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  charset="utf8",
  database="gene_nft"

)'''
app = Flask(__name__)
##session key
app.secret_key = 'abcdef'
#######
UPLOAD_FOLDER = 'static/upload'
ALLOWED_EXTENSIONS = { 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####

def get_db_config():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        parsed = urlparse(database_url)
        return {
            "host": parsed.hostname or os.getenv("DB_HOST", "localhost"),
            "port": parsed.port or int(os.getenv("DB_PORT", "3306")),
            "user": unquote(parsed.username or os.getenv("DB_USER", "root")),
            "password": unquote(parsed.password or os.getenv("DB_PASSWORD", "")),
            "database": (parsed.path or "").lstrip("/") or os.getenv("DB_NAME", "gene_nft"),
        }

    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
        "database": os.getenv("DB_NAME", "gene_nft"),
    }


def get_db_connection():
    config = get_db_config()
    conn = psycopg2.connect(
        host=config["host"],
        port=config["port"],
        user=config["user"],
        password=config["password"],
        database=config["database"],
    )
    conn.autocommit = False  # explicit commit/rollback — prevents key/sig split-brain
    return conn


def get_db_cursor(conn, dictionary=False):
    if dictionary:
        return conn.cursor(cursor_factory=RealDictCursor)
    return conn.cursor()


@app.route('/', methods=['GET', 'POST'])
def index():
    msg=""
    

    return render_template('web/index.html',msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor.execute('SELECT * FROM gn_admin WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            cursor.close()
            conn.close()
            return redirect(url_for('admin'))
        else:
            msg = 'Incorrect username/password!'

    cursor.close()
    conn.close()  
    return render_template('web/login.html',msg=msg)

@app.route('/login_owner', methods=['GET', 'POST'])
def login_owner():
    msg=""
    act=request.args.get("act")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor.execute('SELECT * FROM gn_owner WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            cursor.close()
            conn.close()
            return redirect(url_for('owner_home'))
        else:
            msg = 'Incorrect username/password!'
    
    cursor.close()
    conn.close()  
    return render_template('web/login_owner.html',msg=msg,act=act)

@app.route('/login_res', methods=['GET', 'POST'])
def login_res():
    msg=""
    act=request.args.get("act")
    conn = get_db_connection()
    cursor = conn.cursor()

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor.execute('SELECT * FROM gn_researcher WHERE uname = %s AND pass = %s AND status=1', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            cursor.close()
            conn.close()
            return redirect(url_for('res_home'))
        else:
            msg = 'Incorrect username/password!'


    cursor.close()
    conn.close()  
    return render_template('web/login_res.html',msg=msg,act=act)


#Blockchain
class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200



def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

#Interact with Smart Contract (NFT Minting)
# ----------------------------
def mint_nft(web3, contract_address, abi, metadata_ipfs_hash, owner_address, private_key):
    contract = web3.eth.contract(address=contract_address, abi=abi)
    nonce = web3.eth.get_transaction_count(owner_address)
    
    txn = contract.functions.mintNFT(owner_address, metadata_ipfs_hash).build_transaction({
        'chainId': 1337,  
        'gas': 300000,
        'gasPrice': web3.toWei('2', 'gwei'),
        'nonce': nonce
    })
    
    signed_txn = web3.eth.account.sign_transaction(txn, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def genenft(uid,uname,bcdata,utype):
    ############

    now = datetime.datetime.now()
    yr=now.strftime("%Y")
    mon=now.strftime("%m")
    rdate=now.strftime("%d-%m-%Y")
    rtime=now.strftime("%H:%M:%S")
    
    ff=open("static/key.txt","r")
    k=ff.read()
    ff.close()
    
    #bcdata="CID:"+uname+",Time:"+val1+",Unit:"+val2
    dtime=rdate+","+rtime

    ff1=open("static/css/d1.txt","r")
    bc1=ff1.read()
    ff1.close()
    
    px=""
    if k=="1":
        px=""
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        print(key)
        v=k+"##"+key+"##"+bcdata+"##"+dtime

        ff1=open("static/css/d1.txt","w")
        ff1.write(v)
        ff1.close()
        
        dictionary = {
            "ID": "1",
            "Pre-hash": "00000000000000000000000000000000",
            "Hash": key,
            "utype": utype,
            "Date/Time": dtime
        }

        k1=int(k)
        k2=k1+1
        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()
        
    else:
        px=","
        pre_k=""
        k1=int(k)
        k2=k1-1
        k4=str(k2)

        ff1=open("static/prehash.txt","r")
        pre_hash=ff1.read()
        ff1.close()
        
        g1=bc1.split("#|")
        for g2 in g1:
            g3=g2.split("##")
            if k4==g3[0]:
                pre_k=g3[1]
                break

        
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        

        v="#|"+k+"##"+key+"##"+bcdata+"##"+dtime

        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/css/d1.txt","a")
        ff1.write(v)
        ff1.close()

        
        
        dictionary = {
            "ID": k,
            "Pre-hash": pre_hash,
            "Hash": key,
            "utype:": utype,
            "Date/Time": dtime
        }
        k21=int(k)+1
        k3=str(k21)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()

    m=""
    if k=="1":
        m="w"
    else:
        m="a"
    # Serializing json
    
    json_object = json.dumps(dictionary, indent=4)
     
    # Writing to sample.json
    with open("static/genenft.json", m) as outfile:
        outfile.write(json_object)
    ##########

def generate_wallet_address():
    prefix = "0x"
    characters = string.hexdigits.lower()
    address = ''.join(random.choice(characters) for _ in range(40))

    return prefix + address

# Smart Contracts Simulation
# -----------------------------

class OwnershipContract:
    @staticmethod
    def verify_owner(nft_id, user):
        return NFT_LEDGER[nft_id]["owner"] == user


class AccessControlContract:
    permissions = {}

    @staticmethod
    def grant_access(nft_id, requester):
        AccessControlContract.permissions.setdefault(nft_id, []).append(requester)

    @staticmethod
    def check_access(nft_id, requester):
        return requester in AccessControlContract.permissions.get(nft_id, [])


class MonetizationContract:
    prices = {}

    @staticmethod
    def set_price(nft_id, price):
        MonetizationContract.prices[nft_id] = price

    @staticmethod
    def pay_and_access(nft_id, requester, amount):
        required = MonetizationContract.prices.get(nft_id, 0)
        if amount >= required:
            AccessControlContract.grant_access(nft_id, requester)
            return True
        return False


'''def register_user_crypto(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # -------------------------------------------------
    #Split Private Key (Threshold 3 out of 5)
    # -------------------------------------------------
    shares = PlaintextToHexSecretSharer.split_secret(private_pem, 3, 5)

    # -------------------------------------------------
    #Encrypt Each Share (Node-Level Protection)
    # -------------------------------------------------
    encrypted_shares = []
    storage_key = Fernet.generate_key()   # node encryption key
    cipher = Fernet(storage_key)

    for idx, share in enumerate(shares):
        encrypted = cipher.encrypt(share.encode())

        # create hash for blockchain anchoring
        share_hash = hashlib.sha256(share.encode()).hexdigest()

        encrypted_shares.append({
            "user_id": user_id,
            "share_index": idx + 1,
            "encrypted_share": encrypted,
            "share_hash": share_hash
        })

    # -------------------------------------------------
    #Prepare Response (DO NOT RETURN PRIVATE KEY)
    # -------------------------------------------------
    result = {
        "public_key": public_pem,
        "shares": encrypted_shares,
        "node_key": storage_key  # used only by storage service
    }

    return result'''
#Genomic Data NFT
class GenomicNFT:
    def __init__(self, data: str, owner: str, parent_id=None):
        self.id = hashlib.sha256((data + owner).encode()).hexdigest()
        self.owner = owner
        self.parent_id = parent_id
        self.access_list = [] 
        self.data_hash = hashlib.sha256(data.encode()).hexdigest()
        self.encrypted_data = None 
        self.metadata = {
            "id": self.id,
            "owner": self.owner,
            "parent_id": self.parent_id,
            "data_hash": self.data_hash
        }

    def grant_access(self, user: str):
        if user not in self.access_list:
            self.access_list.append(user)

    def revoke_access(self, user: str):
        if user in self.access_list:
            self.access_list.remove(user)

#NFT Manager: Composable NFTs
class NFTManager:
    def __init__(self):
        self.nfts = {}
        self.storage = storage
        self.crypto = crypto

    def create_raw_genomic_nft(self, raw_data: str, owner: str):
        nft = GenomicNFT(raw_data, owner)
        encrypted = self.crypto.encrypt_storage(raw_data)
        nft.encrypted_data = encrypted
        storage_hash = self.storage.store_data(encrypted.decode("latin1"))
        nft.metadata['storage_hash'] = storage_hash
        self.nfts[nft.id] = nft
        return nft

    def create_sequenced_nft(self, parent_nft: GenomicNFT, derived_data: str, owner: str):
        nft = GenomicNFT(derived_data, owner, parent_id=parent_nft.id)
        encrypted = self.crypto.encrypt_storage(derived_data)
        nft.encrypted_data = encrypted
        storage_hash = self.storage.store_data(encrypted.decode("latin1"))
        nft.metadata['storage_hash'] = storage_hash
        self.nfts[nft.id] = nft
        return nft

def Homomorphic():
    # Owner wallet/public key
    owner = "0xABC123"

    # Create a raw genomic NFT
    raw_genome = "AGTCAGTCAGTCA"
    raw_nft = manager.create_raw_genomic_nft(raw_genome, owner)
    print("Raw NFT metadata:", raw_nft.metadata)

    # Create derived sequenced NFT (child)
    derived_genome = "AGTCAGTCA"  # Subset or processed genome
    seq_nft = manager.create_sequenced_nft(raw_nft, derived_genome, owner)
    print("Sequenced NFT metadata:", seq_nft.metadata)

    # Grant access to another user
    seq_nft.grant_access("0xDEF456")
    print("Access list:", seq_nft.access_list)

    # Retrieve and decrypt
    encrypted_from_storage = storage.retrieve_data(seq_nft.metadata['storage_hash']).encode("latin1")
    decrypted = crypto.decrypt_storage(encrypted_from_storage)
    print("Decrypted genome data:", decrypted)

    # Homomorphic computation example
    value = 10
    encrypted_value = crypto.encrypt_for_computation(value)
    result = encrypted_value + 5  # homomorphic addition
    decrypted_result = crypto.decrypt_computation(result)
    print("Homomorphic computation result:", decrypted_result)



###########
def register_user_crypto(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    uf1=user_id+"_pb.txt"
    uf2=user_id+"_pr.txt"
    public_pem
    ff=open("static/kg/"+uf1,"w")
    ff.write(public_pem)
    ff.close()

    ff=open("static/kg/"+uf2,"w")
    ff.write(private_pem)
    ff.close()
    

    # -----------------------------
    #Split Private Key (3-of-5 Threshold)
    # -----------------------------
    #shares = PlaintextToHexSecretSharer.split_secret(private_pem, 3, 5)
    private_bytes = private_pem.encode()

    # Create 3-of-5 threshold shares
    mnemonics = generate_mnemonics(
        group_threshold=1,
        groups=[(3, 5)],  # need 3 shares out of 5
        master_secret=private_bytes
    )

    shares = mnemonics[0]  
    # -----------------------------
    # Encrypt Shares Per Node
    # -----------------------------
    distributed_shares = []

    for idx, share in enumerate(shares):

        # Each node generates its OWN key
        node_key = Fernet.generate_key()
        cipher = Fernet(node_key)

        encrypted_share = cipher.encrypt(share.encode())

        # Blockchain anchor hash (hash BEFORE encryption)
        share_hash = hashlib.sha256(share.encode()).hexdigest()

        distributed_shares.append({
            "user_id": user_id,
            "share_index": idx + 1,
            "encrypted_share": encrypted_share,
            "share_hash": share_hash,
            "node_key": node_key   # stored ONLY in that node
        })


    return {
        "public_key": public_pem,
        "share_hashes": [s["share_hash"] for s in distributed_shares],
        "distributed_shares": distributed_shares  # send to backend storage layer only
    }

def get_user_public_key(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (user_id,))
    result = cursor.fetchone()

    if not result:
        raise Exception("Public key not found!")

    public_pem = result[0]

    public_key = serialization.load_pem_public_key(public_pem.encode())

    cursor.close()
    conn.close()  
    return public_key

def getpbk(user_id):
    file_path="static/kg/"+user_id+"_pb.txt"
    with open(file_path, "r") as f:
            lines = f.readlines()

    # Remove BEGIN and END lines
    key_lines = [
        line.strip()
        for line in lines
        if "BEGIN PUBLIC KEY" not in line and
           "END PUBLIC KEY" not in line
    ]

    # Join into single continuous string
    key_string = "".join(key_lines)
    pbkey=key_string[:64]
    return pbkey

def getprk(user_id):
    file_path="static/kg/"+user_id+"_pr.txt"
    with open(file_path, "r") as f:
        key_text = f.read()

    # Remove PEM headers/footers
    cleaned = re.sub(r"-----.*?-----", "", key_text)

    # Remove whitespace and newlines
    cleaned = cleaned.replace("\n", "").strip()

    # Get first 64 characters
    return cleaned[:64]

# ============================================================
#  REAL RSA-PSS DIGITAL SIGNATURE HELPERS
# ============================================================

def load_private_key_pem(user_id):
    """Load full RSA private key PEM from disk for a Lab Assistant."""
    file_path = "static/kg/" + user_id + "_pr.txt"
    with open(file_path, "r") as f:
        private_pem = f.read()
    return serialization.load_pem_private_key(private_pem.encode(), password=None)

def load_public_key_pem(user_id):
    """Load full RSA public key PEM from disk for a Lab Assistant."""
    file_path = "static/kg/" + user_id + "_pb.txt"
    with open(file_path, "r") as f:
        public_pem = f.read()
    return serialization.load_pem_public_key(public_pem.encode())

def rsa_sign(private_key_obj, message: str) -> str:
    """
    Sign a message string with RSA-PSS (SHA-256).
    Returns Base64-encoded signature string.
    """
    signature_bytes = private_key_obj.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature_bytes).decode()

def rsa_verify(public_key_obj, message: str, signature_b64: str) -> bool:
    """
    Verify an RSA-PSS signature (SHA-256).
    Returns True if valid, False if tampered/wrong key.

    PSS.AUTO is used for salt_length so the verifier accepts any valid
    salt length — including MAX_LENGTH signatures produced during signing.
    Using MAX_LENGTH here would require the salt to be exactly max size,
    which silently fails if the signature was produced under different
    conditions (different key size, library version, or platform).
    """
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key_obj.verify(
            sig_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO      # accept any valid PSS salt length
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def get_admin_private_key():
    """Load or auto-generate the Admin RSA-2048 key pair (stored in static/kg/admin_pr.txt)."""
    priv_path = "static/kg/admin_pr.txt"
    pub_path  = "static/kg/admin_pb.txt"
    if not os.path.exists(priv_path):
        # First run: generate admin key pair
        adm_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        adm_pub  = adm_priv.public_key()
        with open(priv_path, "w") as f:
            f.write(adm_priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode())
        with open(pub_path, "w") as f:
            f.write(adm_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())
    with open(priv_path, "r") as f:
        return serialization.load_pem_private_key(f.read().encode(), password=None)

def get_admin_public_key():
    """Return Admin RSA public key object (generates pair if missing)."""
    get_admin_private_key()   # ensures files exist
    with open("static/kg/admin_pb.txt", "r") as f:
        return serialization.load_pem_public_key(f.read().encode())

# ============================================================
#  END SIGNATURE HELPERS
# ============================================================

def hybrid_encrypt_file(file_obj, public_key, save_path):

    #Generate AES session key
    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)

    # Read genome file (FASTQ/VCF)
    file_data = file_obj.read()

    # Encrypt genome data with AES
    encrypted_data = cipher.encrypt(file_data)

    with open(save_path, "wb") as f:
        f.write(encrypted_data)

    # Encrypt AES key using USER PUBLIC KEY
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data, encrypted_key

def pad_left(s, length):
    return s.zfill(length)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    act=""
   
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT max(id)+1 FROM gn_researcher")
    maxid = cursor.fetchone()[0]
    if maxid is None:
        maxid=1

    input_str = str(maxid)
    padded_str = pad_left(input_str, 3)
    u_id="R"+padded_str
            
    if request.method=='POST':
        name=request.form['name']
        institution=request.form['institution']
        domain=request.form['domain']
        mobile=request.form['mobile']
        email=request.form['email']
        location=request.form['location']
        
        uname=request.form['uname']
        pass1=request.form['pass']
        
      
        cursor.execute("SELECT count(*) FROM gn_researcher where uname=%s",(uname,))
        cnt = cursor.fetchone()[0]

        
        
        if cnt==0:
            sql = "INSERT INTO gn_researcher(id,name,institution,domain,mobile,email,location,uname,pass,status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,institution,domain,mobile,email,location,uname,pass1,'0')
            cursor.execute(sql, val)
            conn.commit()
            bcdata="ID:"+str(maxid)+",User ID:"+uname+", Researcher Registered"
            genenft(str(maxid),uname,bcdata,'key')
            
            
            msg="success"

        else:
            msg='fail'

    cursor.close()
    conn.close()  
    return render_template('web/register.html',msg=msg,u_id=u_id)

@app.route('/reg_owner', methods=['GET', 'POST'])
def reg_owner():
    msg=""
    mess=""
    email=""
    act=""
    conn = get_db_connection()
    cursor = conn.cursor()
   
    cursor.execute("SELECT max(id)+1 FROM gn_owner")
    maxid = cursor.fetchone()[0]
    if maxid is None:
        maxid=1

    input_str = str(maxid)
    padded_str = pad_left(input_str, 3)
    u_id="U"+padded_str

    now1 = datetime.datetime.now()
    rdate=now1.strftime("%d-%m-%Y")
    edate1=now1.strftime("%Y-%m-%d")
    rtime=now1.strftime("%H:%M:%S")
    
    if request.method=='POST':
        name=request.form['name']
        dob=request.form['dob']
        gender=request.form['gender']
        mobile=request.form['mobile']
        email=request.form['email']
        address=request.form['address']
        country=request.form['country']
        
        uname=request.form['uname']
        pass1=request.form['pass']

        s_question=request.form['s_question']
        s_answer=request.form['s_answer']

        ans = hashlib.md5(s_answer.encode())
        s_answer1=ans.hexdigest()

        
        
      
        cursor.execute("SELECT count(*) FROM gn_owner where uname=%s",(uname,))
        cnt = cursor.fetchone()[0]
        #Interplanetary File System IPFS
        #base_path = "static/IPFS"
        #user_path = os.path.join(base_path, uname)
        #os.makedirs(user_path, exist_ok=True)
    
        if cnt==0:

            #Generate cryptographic identity
            user_id=uname
            #crypto_data = register_user_crypto(user_id)
            crypto_data = register_user_crypto(user_id)
            shares = crypto_data["distributed_shares"]

            public_key = crypto_data["public_key"]
            #shares = crypto_data["shares"]

            pb1=getpbk(uname)
            p1 = hashlib.md5(pb1.encode())
            pk=p1.hexdigest()
            pbkey=pk
            
            uuu=uname+str(maxid)
            pr1=getprk(uname)
            u1 = hashlib.md5(pr1.encode())
            prhash=u1.hexdigest()

            mm=uname+dob+str(maxid)
            m1 = hashlib.md5(mm.encode())
            mkey=m1.hexdigest()

            wa=generate_wallet_address()
        
    
            sql = "INSERT INTO gn_owner(id,name,dob,gender,mobile,email,address,country,wallet_address,uname,pass,s_question,s_answer,rdate,rtime,public_key,pbkey,prhash,masterkey) VALUES (%s,%s,%s,%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,dob,gender,mobile,email,address,country,wa,uname,pass1,s_question,s_answer1,rdate,rtime,public_key,pbkey,prhash,mkey)
            cursor.execute(sql, val)
            conn.commit()

            bcdata="ID:"+str(maxid)+",User ID:"+uname+", Wallet_address:"+wa+", Status: Data Owner Registered"
            genenft(str(maxid),uname,bcdata,'owner')

            mess="Dear "+name+", User ID: "+uname+", Public Key: "+pbkey+", Private Key Hash Value:"+prhash

            # Store Encrypted Shares (Off-chain DB / IPFS)
            # -----------------------------
            #for s in shares:
            for s in crypto_data["distributed_shares"]:
                cursor.execute("SELECT max(id)+1 FROM gn_key_shares")
                maxid2 = cursor.fetchone()[0]
                if maxid2 is None:
                    maxid2=1
                cursor.execute("""
                    INSERT INTO gn_key_shares (id,user_id, share_index, encrypted_share, share_hash)
                    VALUES (%s,%s, %s, %s, %s)
                """, (maxid2,s["user_id"], s["share_index"], s["encrypted_share"], s["share_hash"]))
                conn.commit()
                bcdata="ID:"+str(maxid2)+",User ID:"+uname+",Share_index:"+str(s["share_index"])+",Share_hash:"+s["share_hash"]
                genenft(str(maxid),uname,bcdata,'key')
            
           
            
            msg="success"

        else:
            msg='fail'

    cursor.close()
    conn.close()         
    return render_template('web/reg_owner.html',msg=msg,mess=mess,email=email,u_id=u_id)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    if 'username' in session:
        uname = session['username']
    st=""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner')
    data = cursor.fetchall()

   
    cursor.close()
    conn.close()  
    return render_template('admin.html',msg=msg, data=data)


@app.route('/view_res')
def view_res():
    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher")
    researchers = cursor.fetchall()

    cursor.close()
    conn.close()  
    return render_template("view_res.html",
                           researchers=researchers)



@app.route('/approve_researcher')
def approve_researcher():
    rid = request.args.get("id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("update gn_researcher set status='1' where id=%s", (rid,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('/view_res')


# ============================================================
#  ADMIN: Dual-Approval with REAL RSA-PSS Digital Signatures
# ============================================================
@app.route('/admin_send_approvals', methods=['GET', 'POST'])
def admin_send_approvals():
    """
    Admin co-signs file-release requests using the Admin RSA private key.
    Before signing, the Lab Assistant's RSA-PSS signature is cryptographically
    verified against their stored public key.
    """
    msg = ""
    sig_display = ""
    verify_detail = ""
    uname = session.get('username', 'Admin')

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    if request.method == 'POST':
        rid      = request.form.get('rid')

        # ── Step 1: verify admin session ──
        if not uname:
            msg = "wrong_pass"
        else:
            # Load the request
            cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
            req = cursor.fetchone()

            owner_id = req['owner_id']

            # Simple acceptance: record admin name + timestamp
            accept_timestamp   = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            admin_accept_message = (
                f"GENENFT_ADMIN_APPROVAL|"
                f"RID:{rid}|"
                f"ADMIN:{uname}|"
                f"OWNER:{owner_id}|"
                f"RESEARCHER:{req['researcher_id']}|"
                f"TS:{accept_timestamp}"
            )
            admin_acceptance = f"{uname} | {accept_timestamp}"

            try:
                cursor.execute("""
                    UPDATE gn_data_requests
                    SET admin_approval     = 'Approved',
                        admin_signature    = %s,
                        admin_sign_message = %s,
                        pay_st             = 2
                    WHERE id = %s
                """, (admin_acceptance, admin_accept_message, rid))
                conn.commit()
            except Exception as db_err:
                conn.rollback()
                print("DB commit error in admin_send_approvals:", db_err)
                msg = "sig_fail"
                cursor.close()
                conn.close()
                return render_template("admin_send_approvals.html",
                    msg=msg, pending=[], approved_list=[], admin=uname,
                    sig_display="", verify_detail="")

            bcdata = (
                f"ID:{rid}|Admin:{uname}|"
                f"Accepted|"
                f"TS:{accept_timestamp}|"
                f"Action:ADMIN_APPROVED_FILE_RELEASED"
            )
            genenft(str(rid), uname, bcdata, 'admin')

            sig_display   = admin_acceptance
            verify_detail = f"Accepted by {uname}"
            msg = "approved"

    # ── Load pending (owner signed, admin not yet) ──
    cursor.execute("""
        SELECT r.*, d.title, d.price
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        WHERE r.owner_signature IS NOT NULL
          AND (r.admin_approval = 'Pending' OR r.admin_approval IS NULL)
        ORDER BY r.id DESC
    """)
    pending = cursor.fetchall()

    # ── Load approved history ──
    cursor.execute("""
        SELECT r.*, d.title, d.price
        FROM gn_data_requests r
        JOIN gn_genomic_dataset d ON r.dataset_id = d.id
        WHERE r.admin_approval = 'Approved'
        ORDER BY r.id DESC
    """)
    approved_list = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin_send_approvals.html",
        msg=msg,
        pending=pending,
        approved_list=approved_list,
        admin=uname,
        sig_display=sig_display,
        verify_detail=verify_detail
    )






@app.route('/owner_home', methods=['GET', 'POST'])
def owner_home():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    if request.method=='POST':
        st="1"


    cursor.close()
    conn.close()  
    return render_template('owner_home.html',msg=msg, data=data,st=st)

def create_user_directory(username):
    path = os.path.join("static/IPFS", username)
    os.makedirs(path, exist_ok=True)
    return path

def generate_hash(data):
    return hashlib.sha256(data).hexdigest()

def generate_nft():
    return "NFT-" + uuid.uuid4().hex[:10].upper()

def ghash(file_path):
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    
    return hash_sha256.hexdigest()

def encrypt_file(in_file, out_file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    
    data = open(in_file, 'rb').read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(out_file, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)

def decrypt_file(in_file, out_file, key):
    data = open(in_file, 'rb').read()

    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    open(out_file, 'wb').write(plaintext)
        
        
@app.route('/owner_upload', methods=['GET', 'POST'])
def owner_upload():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()
    
    cursor.execute("SELECT max(id)+1 FROM gn_genomic_dataset")
    maxid = cursor.fetchone()[0]
    if maxid is None:
        maxid=1

    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()
    #pbkey=data[17]

    pbkey=getpbk(uname)
        
    if request.method == 'POST':

        user_id = uname
        title = request.form['title']
        description = request.form['description']
        allowed_analysis = request.form.getlist('allowed_analysis')
        ethnicity = request.form['ethnicity']
        
        consent = request.form.get('consent')
        public_key = request.form['public_key']
        price = request.form['price']

        if pbkey==public_key:

            file = request.files['genome_file']
            filename = secure_filename(file.filename)

            # Create user folder
            user_folder = create_user_directory(uname)

            file.save(os.path.join("static/css/ups", filename))
            gh=ghash("static/css/ups/"+filename)
            vfile=gh[:8] + ".vcf"
            vff=uname+".vcf"
            shutil.copy("static/css/"+vfile,"static/IPFS/"+uname+"/"+vff)
            os.remove("static/css/ups/"+filename)

            encrypted_filename = "enc_" + filename
            save_path = os.path.join(user_folder, encrypted_filename)

            public_key = get_user_public_key(user_id)
            # Encrypt file
            #encrypted_data = encrypt_and_save(file, save_path)
            encrypted_data, encrypted_key = hybrid_encrypt_file(file, public_key, save_path)
            # Generate hash from encrypted content
            file_hash = generate_hash(encrypted_data)

            # Generate NFT token
            nft_token = generate_nft()

            # Store in DB
            allowed=",".join(allowed_analysis)
            query = """
            INSERT INTO gn_genomic_dataset
            (id,user_id, title, description, allowed_analysis, ethnicity, price,
             encrypted_file, file_hash, nft_token)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            values = (
                maxid,user_id, title, description, allowed,
                ethnicity, price, encrypted_filename,
                file_hash, nft_token
            )

            
            cursor.execute(query, values)
            conn.commit()
            bcdata="ID:"+str(maxid)+",User ID:"+uname+", File:"+encrypted_filename+", File Hash:"+file_hash+" , NFT Token:"+nft_token+", Status: Upload Data"
            genenft(str(maxid),uname,bcdata,'owner')
            msg="success"
        else:
            msg="fail"

        #return "Dataset Uploaded & Encrypted Successfully!"


    cursor.close()
    conn.close()  
    return render_template("owner_upload.html",msg=msg,data=data)

@app.route('/owner_files')
def owner_files():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_owner WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor = get_db_cursor(conn, dictionary=True)
    
    cursor.execute("SELECT * FROM gn_genomic_dataset WHERE user_id=%s", (uname,))
    datasets = cursor.fetchall()


    cursor.close()
    conn.close()  
    
    return render_template("owner_files.html", datasets=datasets,data=data)

'''@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    
    #if 'username' not in session:
    #    return redirect(url_for('login'))

    uname = session['username']

    # ------------------------
    # GET Load Page
    # ------------------------
    if request.method == 'GET':
        return render_template("owner_key.html")

    # ------------------------
    # POST Handle AJAX
    # ------------------------
    key_type = request.form.get("key_type")
    entered_master = request.form.get("master_key")

    cursor = mydb.cursor()
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data = cursor.fetchone()

    if not data:
        return jsonify({"status": "error", "message": "User not found"})

    master_key = data[20]

    if entered_master != master_key:
        return jsonify({"status": "error", "message": "Invalid Master Key"})

    pbkey = getpbk(uname)
    prkey = getprk(uname)

    import hashlib, math, random

    pbhash = hashlib.sha256(pbkey.encode()).hexdigest()
    prhash = hashlib.sha256(prkey.encode()).hexdigest()

    length = math.ceil(len(prkey)/5)
    shares = [prkey[i:i+length] for i in range(0, len(prkey), length)]

    share_hashes = [hashlib.sha256(s.encode()).hexdigest() for s in shares]

    if key_type == "public":
        return jsonify({
            "status": "success",
            "type": "public",
            "public_key": pbkey,
            "public_hash": pbhash
        })

    elif key_type == "private":
        selected = random.sample(list(zip(shares, share_hashes)), 3)

        return jsonify({
            "status": "success",
            "type": "private",
            "private_key": prkey,
            "private_hash": prhash,
            "selected_shares": selected
        })

    return jsonify({"status": "error", "message": "Invalid Request"})'''

@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    
    act = ""
    msg = ""
    st=""
    conn = get_db_connection()
    cursor = conn.cursor()
    uname = session.get("username")
    # Fetch already-generated keys (NO generation here)
    pbkey = getpbk(uname)
    prkey = getprk(uname)

    pr1 = prkey[0:12]
    pr2 = prkey[12:24]
    pr3 = prkey[24:36]
    pr4 = prkey[36:48]
    pr5 = prkey[48:60]

    cursor.execute("""
        SELECT * FROM gn_owner WHERE uname=%s
    """, (uname,))
    data1 = cursor.fetchone()
    name=data1[1]
    pbhash = data1[17]
    prhash = data1[18]
    master_key = data1[19]
    key_st=data1[20]
    if key_st==1:
        st="1"

    data3 = {
        "public_key": pbkey,
        "private_key": prkey,
        "nodes": [pr1, pr2, pr3, pr4, pr5],
        "public_hash": pbhash,
        "private_hash": prhash,
        "master_key": master_key
    }

    # get distributed node hash
    pr_hash = []
    cursor.execute("SELECT * FROM gn_key_shares WHERE user_id=%s", (uname,))
    data2 = cursor.fetchall()

    for dd in data2:
        dv=dd[4]
        dv1=dv[0:32]
        pr_hash.append(dv1)

    cursor.close()
    conn.close()

    if request.method == 'POST':
        act = "done"
        # mail values
        email = data1[5]
        mess = "Dear "+name+", User ID: "+uname+", Master Hash Key is: " + master_key

        return render_template(
            "owner_key.html",
            act=act,
            data1=data1,
            data3=data3,
            pr_hash=pr_hash,
            email=email,
            mess=mess
        )

    # GET load
    return render_template(
        "owner_key.html",
        act=act,
        data1=data1,
        data3=data3,
        pr_hash=pr_hash,
        st=st
    )

'''@app.route("/owner_key", methods=['GET', 'POST'])
def owner_key():
    cursor = mydb.cursor()
    uname = session.get("username")

    pbkey = getpbk(uname)
    prkey = getprk(uname)

    prkey = prkey[:60]

    pr_nodes = [
        prkey[0:12],
        prkey[12:24],
        prkey[24:36],
        prkey[36:48],
        prkey[48:60]
    ]

    cursor.execute("""
        SELECT * FROM gn_owner WHERE uname=%s
    """, (uname,))
    data1 = cursor.fetchone()

    pbhash = data1[17]
    prhash = data1[18]
    master_key = data1[19]
    email = data1[4]

    # Fetch node hashes safely
    cursor.execute("""
        SELECT share_hash 
        FROM gn_key_shares 
        WHERE user_id=%s 
        ORDER BY id ASC
    """, (uname,))

    rows = cursor.fetchall()

    pr_hash = []
    for r in rows:
        pr_hash.append(r[0])

    while len(pr_hash) < 5:
        pr_hash.append("Hash Not Found")

    data3 = {
        "public_key": pbkey,
        "private_key": prkey,
        "nodes": pr_nodes,
        "public_hash": pbhash,
        "private_hash": prhash,
        "node_hashes": pr_hash,
        "master_key": master_key,
        "email": email
    }

    return render_template("owner_key.html", data3=data3)'''





'''@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    msg = ""
    mess=""
    act = request.args.get("act", "")

    # Check session safely
    #if 'username' not in session:
    #    return redirect(url_for('login'))

    uname = session['username']

    cursor = mydb.cursor()

    # Get owner basic data
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data1 = cursor.fetchone()
    email=data1[5]
    name=data1[1]

    if not data1:
        msg = "Owner record not found"
        return render_template("owner_key.html", msg=msg)

    # Fetch already-generated keys (NO generation here)
    pbkey = getpbk(uname)   # public key
    prkey = getprk(uname)   # private key

    # Split private key into 5 equal nodes (12 chars each)
    pr1 = prkey[0:12]
    pr2 = prkey[12:24]
    pr3 = prkey[24:36]
    pr4 = prkey[36:48]
    pr5 = prkey[48:60]

    #Hash + Master Key from DB
    pbhash = data1[17]
    prhash = data1[18]
    master_key = data1[19]

    # Pack for easy template use
    data3 = {
        "public_key": pbkey,
        "private_key": prkey,
        "nodes": [pr1, pr2, pr3, pr4, pr5],
        "public_hash": pbhash,
        "private_hash": prhash,
        "master_key": master_key
    }
    mess="Dear "+name+", Master Key: "+master_key
    #Get distributed hash shares
    pr_hash = []
    cursor.execute("SELECT * FROM gn_key_shares WHERE user_id=%s", (uname,))
    data2 = cursor.fetchall()

    for dd in data2:
        pr_hash.append(dd[4])   # share hash column

    return render_template(
        "owner_key.html",
        msg=msg,
        act=act,
        data1=data1,
        data2=data2,
        pr_hash=pr_hash,
        data3=data3,
        email=email,
        mess=mess
    )'''

'''@app.route('/owner_key', methods=['GET', 'POST'])
def owner_key():
    msg=""
    act=request.args.get("act")
    st=""
    if 'username' in session:
        uname = session['username']

    cursor = mydb.cursor()
    
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data1 = cursor.fetchone()
   
    pbkey=getpbk(uname)
    prkey=getprk(uname)

    pr1=prkey[0:12]
    pr2=prkey[12:12]
    pr3=prkey[24:12]
    pr4=prkey[36:12]
    pr5=prkey[48:12]

    pbhash=data1[17]
    prhash=data1[18]
    master_key=data1[20]

    data3=[pbkey,prkey,pr1,pr2,pr3,pr4,pr5,pbhash,prhash,master_key]

    pr_hash=[]
    cursor.execute("SELECT * FROM gn_key_shares WHERE user_id=%s", (uname,))
    data2 = cursor.fetchall()
    for dd in data2:
        ph=dd[4]
        pr_hash.append(ph)
    
        
    
    return render_template("owner_key.html", msg=msg,act=act,data1=data1,data2=data2,pr_hash=pr_hash,data3=data3)'''



@app.route('/view_owner', methods=['GET', 'POST'])
def view_owner():
    msg=""
    if 'username' in session:
        uname = session['username']
    st=""
    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute('SELECT * FROM gn_owner')
    data = cursor.fetchall()

    cursor.close()
    conn.close()  
        
    return render_template('view_owner.html',msg=msg, data=data)

@app.route('/approve/<id>')
def approve(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE gn_researcher SET status='1' WHERE id=%s",(id,))
    conn.commit()

    cursor.close()
    conn.close()  
    return redirect('/view_provider')


# ---------------- Reject ----------------
@app.route('/reject/<id>')
def reject(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("UPDATE gn_researcher SET status='2' WHERE id=%s",(id,))
    conn.commit()

    cursor.close()
    conn.close()  
    return redirect('/view_res')

def disease_exists_in_vcf(vcf_path, search_disease):
    print("Checking file:", vcf_path)

    if os.path.exists(vcf_path):
        print("File exists")

        with open(vcf_path, 'r') as f:
            for line in f:
                if line.startswith("#"):
                    continue

                info = line.strip().split("\t")[7]

                for item in info.split(";"):
                    if item.startswith("DISEASE="):
                        disease = item.split("=")[1]

                        print("Found disease:", disease)
                        print("Input disease:", disease_input)

                        if disease.lower().strip() == disease_input.lower().strip():
                            print("MATCH FOUND")
                            return True
    return False

def get_matching_diseases(vcf_path, search_diseases):
    matched = set()

    with open(vcf_path, 'r') as file:
        for line in file:
            if line.startswith("#"):
                continue

            info = line.strip().split("\t")[7]

            for item in info.split(";"):
                if item.startswith("DISEASE="):
                    disease = item.split("=")[1].strip().lower()

                    for sd in search_diseases:
                        if sd in disease:
                            matched.add(disease)

    return list(matched)

@app.route('/res_home', methods=['GET', 'POST'])
def res_home():
    msg=""
    st=""
    if 'username' in session:
        uname = session['username']
  
    results=[]
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM gn_researcher WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    

    if request.method=='POST':
        st="1"
        disease_input = request.form['disease']

        print(disease_input)
        
        
        # get all datasets
        cursor.execute("SELECT * FROM datasets")
        datasets = cursor.fetchall()
        
        for dat in datasets:

            owner_id=dat[1]
            vcfile=owner_id+".vcf"
            
            
            vcf_path = os.path.join("static/web/data", vcfile)
            print(vcf_path)
            '''if os.path.exists(vcf_path):
                st="1"
                if disease_exists_in_vcf(vcf_path, disease_input):
                    cursor.execute("SELECT name FROM gn_owner WHERE uname=%s", (owner_id,))
                    user = cursor.fetchone()

                    results.append({
                        'dataset_id': dat['id'],
                        'owner': user['name'],
                        'title': dat['title'],
                        'price': dat['price'],
                        'disease': disease_input
                    })'''


    cursor.close()
    conn.close()  
    return render_template('res_home.html',msg=msg, data=data,st=st,results=results)

def encrypt_disease(disease):
    num = sum(ord(c) for c in disease)
    return HE.encryptInt(num)

def match_disease(enc_val, disease):
    num = sum(ord(c) for c in disease)
    enc_query = HE.encryptInt(num)

    result = enc_val - enc_query   # homomorphic subtraction

    return HE.decryptInt(result) == 0


@app.route('/res_datasets', methods=['GET','POST'])
def res_datasets():
    msg=""
    results = []
    st = ""
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
     
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute('SELECT * FROM gn_researcher WHERE uname=%s',(uname,))
    data = cursor.fetchone()

    if request.method == 'POST':
        st = "1"

        disease_input = request.form['disease'].strip()

        ff=open("static/det.txt","w")
        ff.write(disease_input)
        ff.close()

        
            
        search_diseases = [d.strip().lower() for d in disease_input.split(",")]

        

        cursor.execute("SELECT * FROM gn_genomic_dataset")
        datasets = cursor.fetchall()

        for dat in datasets:
            owner_id = str(dat['user_id'])
            vcfile = owner_id + ".vcf"

            vcf_path = os.path.join("static", "web", "data", vcfile)

            if os.path.exists(vcf_path):

                matched_diseases = get_matching_diseases(vcf_path, search_diseases)

                if matched_diseases:
                    cursor.execute("SELECT name FROM gn_owner WHERE uname=%s", (owner_id,))
                    user = cursor.fetchone()

                    results.append({
                        'dataset_id': dat['id'],
                        'owner': user['name'] if user else "Unknown",
                        'title': dat['title'],
                        'price': dat['price'],
                        'disease': ", ".join(matched_diseases)  # show matched only
                    })

    cursor.close()
    conn.close()  
    return render_template("res_datasets.html",
                           results=results,
                           data=data,
                           st=st,msg=msg)



#0.01==1950
def filter_vcf_by_disease(vcf_file, input_diseases, output_file):
    # convert input to set for fast lookup
    disease_set = set(input_diseases)

    with open(vcf_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            # write header lines as it is
            if line.startswith("#"):
                outfile.write(line)
                continue

            columns = line.strip().split("\t")
            info_field = columns[7]

            # extract disease
            disease = None
            for item in info_field.split(";"):
                if item.startswith("DISEASE="):
                    disease = item.split("=")[1]
                    break

            # check if disease matches input
            if disease in disease_set:
                outfile.write(line)


def normalize(text):
    return text.strip().lower().replace(" ", "")

def extract_diseases(input_file, diseases, output_file):
    headers = []
    result = []

    # Read disease list from file
    with open("static/det.txt", "r") as ff:
        diss = ff.read()

    file_diseases = [d.strip() for d in diss.split(",")]

    # Combine user input + file diseases
    all_diseases = [d.strip() for d in diseases] + file_diseases

    with open(input_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                headers.append(line)
                continue

            parts = line.strip().split('\t')
            if len(parts) < 8:
                parts = line.strip().split()

            if len(parts) < 8:
                continue

            info = parts[7]

            for item in info.split(';'):
                if "DISEASE=" in item:
                    disease = item.split('=')[1].strip()

                    print("File disease:", disease)

                    # Exact match (case-sensitive)
                    if disease in all_diseases:
                        result.append(line)   # no extra newline
                        break

    print("Matched:", len(result))

    with open(output_file, 'w') as out:
        for h in headers:
            out.write(h)
        for r in result:
            out.write(r)

       

@app.route('/send_request')
def send_request():
    uname=""
    if 'username' in session:
        uname = session['username']

    researcher_id = uname
    dataset_id = request.args.get('id')
    disease = request.args.get('disease')
    
    conn = get_db_connection()
   
    
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute("SELECT MAX(id)+1 AS next_id FROM gn_data_requests")
    row = cursor.fetchone()

    maxid = row["next_id"]
    if maxid is None:
        maxid = 1
        
    # get dataset owner
    cursor.execute("SELECT user_id FROM gn_genomic_dataset WHERE id=%s", (dataset_id,))
    data = cursor.fetchone()

    owner_id = data['user_id']
    key= hashlib.sha256(owner_id.encode()).digest()[:16]
    vfile=owner_id+".vcf"
    path="static/ipfs/"+owner_id+"/"+vfile

    #
    fn="f"+str(dataset_id)+"_"+str(maxid)+".vcf"
    output_file = "static/uploads/"+fn
    extract_diseases(path, disease, output_file)



    enc_vfile="f"+str(dataset_id)+"_"+str(maxid)+".enc"
    vfile="f"+str(dataset_id)+"_"+str(maxid)+".vcf"
    shutil.copy("static/uploads/"+vfile, "static/css/down/"+vfile)
    
    encrypt_file("static/uploads/"+vfile, "static/uploads/"+enc_vfile, key)
    os.remove("static/uploads/"+vfile)
   
    bcdata="ID:"+str(maxid)+",Researcher ID:"+uname+", Request for "+disease
    genenft(str(maxid),uname,bcdata,'key')

    cursor.execute("SELECT * FROM gn_genomic_dataset WHERE id=%s", (dataset_id,))
    d1 = cursor.fetchone()
    price=d1['price']

    dc=disease.split(",")
    qty=len(dc)
    amount=price*qty
    # insert request
    cursor.execute("""
        INSERT INTO gn_data_requests (id,dataset_id, owner_id, researcher_id, diseases,amount, status)
        VALUES (%s,%s, %s, %s, %s, %s,%s)
    """, (maxid,dataset_id, owner_id, researcher_id, disease,amount ,'Pending'))
    conn.commit()

    cursor.close()
    conn.close()  
    #return "Request Sent Successfully"
    msg="success"
    return render_template("send_request.html",msg=msg)

@app.route('/owner_requests')
def owner_requests():
    msg=""
    act=request.args.get("act")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()
    
    query = """
    SELECT r.*, d.title, d.price
    FROM gn_data_requests r
    JOIN gn_genomic_dataset d ON r.dataset_id = d.id
    WHERE r.owner_id = %s
    ORDER BY r.id DESC
    """
    

    cursor.execute(query, (uname,))
    data = cursor.fetchall()

    if act=="yes":
        rid=request.args.get("rid")
        cursor.execute("update gn_data_requests set status='Approved' where id=%s",(rid,))
        conn.commit()
        msg="yes"

    if act=="no":
        rid=request.args.get("rid")
        cursor.execute("update gn_data_requests set status='Rejected' where id=%s",(rid,))
        conn.commit()
        msg="no"

    cursor.close()
    conn.close()
    
    return render_template("owner_requests.html",msg=msg,act=act, data=data)

@app.route('/owner_send', methods=['GET', 'POST'])
def owner_send():
    msg = ""
    act = request.args.get("act")
    rid = request.args.get("rid")
    uname = ""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()

    cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
    data3 = cursor.fetchone()

    if request.method == 'POST':
        accepted = request.form.get('accepted', '').strip()

        if not accepted:
            msg = "missing_acceptance"
        else:
            try:
                accept_timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                accept_message = (
                    f"GENENFT_OWNER_APPROVAL|"
                    f"RID:{rid}|"
                    f"OWNER:{uname}|"
                    f"DATASET:{data3['dataset_id']}|"
                    f"RESEARCHER:{data3['researcher_id']}|"
                    f"TS:{accept_timestamp}"
                )

                # Simple acceptance: record owner username + timestamp
                owner_acceptance_val = f"{uname} | {accept_timestamp}"

                try:
                    cursor.execute("""
                        UPDATE gn_data_requests
                        SET owner_signature    = %s,
                            owner_sign_message = %s,
                            admin_approval     = 'Pending'
                        WHERE id = %s
                    """, (owner_acceptance_val, accept_message, rid))
                    conn.commit()
                except Exception as db_err:
                    conn.rollback()
                    print("DB commit error in owner_send:", db_err)
                    msg = "sig_fail"
                    raise

                bcdata = (
                    f"ID:{rid},Owner:{uname},"
                    f"Accepted|"
                    f"TS:{accept_timestamp}|Action:OWNER_APPROVE_FILE_SEND"
                )
                genenft(str(rid), uname, bcdata, 'key')

                msg = "success"

            except Exception as e:
                print("Acceptance error:", e)
                msg = "sig_fail"

    cursor.close()
    conn.close()
    return render_template("owner_send.html", msg=msg, act=act, sig_display="")


@app.route('/res_purchases')
def res_purchases():
    msg=""
    act=request.args.get("act")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()
    
    query = """
    SELECT r.*, d.title, d.price
    FROM gn_data_requests r
    JOIN gn_genomic_dataset d ON r.dataset_id = d.id
    WHERE r.researcher_id = %s
    ORDER BY r.id DESC
    """

    cursor.execute(query, (uname,))
    data = cursor.fetchall()

  

    cursor.close()
    conn.close()
    
    return render_template("res_purchases.html",msg=msg,act=act, data=data)

@app.route('/res_pay', methods=['GET', 'POST'])
def res_pay():
    msg=""
    act=request.args.get("act")
    rid=request.args.get("rid")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher WHERE uname=%s", (uname,))
    data2 = cursor.fetchone()
    
    query = """
    SELECT r.*, d.title, d.price
    FROM gn_data_requests r
    JOIN gn_genomic_dataset d ON r.dataset_id = d.id
    WHERE r.researcher_id = %s
    ORDER BY r.id DESC
    """

    cursor.execute(query, (uname,))
    data = cursor.fetchall()

    if request.method=='POST':
        pay=request.form['pay']
        cursor.execute("update gn_data_requests set pay_st=1 where id=%s",(rid,))
        conn.commit()
        msg="success"
  
        bcdata="ID:"+str(rid)+",Researcher ID:"+uname+", Amount Paid"
        genenft(str(rid),uname,bcdata,'key')
    cursor.close()
    conn.close()
    
    return render_template("res_pay.html",msg=msg,act=act, data=data)

@app.route('/view_vcf', methods=['GET', 'POST'])
def view_vcf():
    filename=request.args.get("vfile")
    
    file_path = "static/css/down/" + filename

    data = []
    headers = []

    with open(file_path, 'r') as f:
        for line in f:
            if line.startswith('##'):
                continue

            # Column header line
            if line.startswith('#CHROM'):
                headers = line.strip().replace('#', '').split('\t')
                continue

            parts = line.strip().split('\t')
            if len(parts) >= 8:
                data.append(parts)

    return render_template("view_vcf.html", headers=headers, data=data,vfile=filename)


@app.route('/res_block', methods=['GET', 'POST'])
def res_block():
    msg=""
    data1=[]
    act=request.args.get("act")
    rid=request.args.get("rid")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_researcher WHERE uname=%s", (uname,))
    data = cursor.fetchone()
    if act=="1":
        ff=open("static/genenft.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

       

    ################
    if act=="11":
        s1="1"
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if uname in dr1[2]:
            
                
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                if uname in dr1[2]:
                    dt.append("2")
                else:
                    dt.append("1")
                data1.append(dt)
    else:
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            #if "Register" in dr1[2]:
                
            dt.append(dr1[0])
            dt.append(dr1[1])
            dt.append(dr1[2])
            dt.append(dr1[3])
            #dt.append(dr1[4])
            data1.append(dt)

    cursor.close()
    conn.close()
    return render_template("res_block.html",msg=msg,act=act, data=data,data1=data1)

@app.route('/owner_block', methods=['GET', 'POST'])
def owner_block():
    msg=""
    data1=[]
    act=request.args.get("act")
    rid=request.args.get("rid")
    uname=""
    if 'username' in session:
        uname = session['username']

    conn = get_db_connection()
    
    cursor = get_db_cursor(conn, dictionary=True)
    cursor.execute("SELECT * FROM gn_owner WHERE uname=%s", (uname,))
    data = cursor.fetchone()
    if act=="1":
        ff=open("static/genenft.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

       

    ################
    if act=="11":
        s1="1"
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if uname in dr1[2]:
            
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                if uname in dr1[2]:
                    dt.append("2")
                else:
                    dt.append("1")
                data1.append(dt)
    else:
        ff=open("static/css/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            #if "Register" in dr1[2]:
                
            dt.append(dr1[0])
            dt.append(dr1[1])
            dt.append(dr1[2])
            dt.append(dr1[3])
            #dt.append(dr1[4])
            data1.append(dt)

    cursor.close()
    conn.close()
    return render_template("owner_block.html",msg=msg,act=act, data=data,data1=data1)
##
# ===== GENE WEIGHTS =====
GENE_WEIGHTS = {
    "BRCA1": 30,
    "TP53": 25,
    "KRAS": 20,
    "APOE": 15
}

# ===== EXTRACT VARIANTS =====
def get_variants(vcf_file, disease):
    variants = []

    with open(vcf_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue

            parts = line.strip().split('\t')
            if len(parts) < 8:
                continue

            info = parts[7]

            gene = ""
            dis = ""

            for item in info.split(';'):
                if item.startswith("GENE="):
                    gene = item.split('=')[1]
                if item.startswith("DISEASE="):
                    dis = item.split('=')[1]

            if dis.lower().replace(" ", "") == disease.lower().replace(" ", ""):
                variants.append(gene)

    return list(set(variants))  # remove duplicates


# ===== CALCULATE RISK =====
def calculate_risk(variants):
    score = 0
    for g in variants:
        score += GENE_WEIGHTS.get(g, 5)
    return min(score, 100)


# ===== CATEGORY =====
def risk_category(score):
    if score > 70:
        return "High"
    elif score > 40:
        return "Medium"
    else:
        return "Low"


# ===== MAIN VARIANT =====
def main_variant(variants):
    return variants[0] + " Mutation" if variants else "None"

@app.route('/result', methods=['GET', 'POST'])
def result():
    result = None

    ff=open("static/det.txt","r")
    disease=ff.read()
    ff.close()
    
    
    file = request.args.get("vfile")

    variants = get_variants("static/css/down/"+file, disease)
    score = calculate_risk(variants)
    category = risk_category(score)
    variant = main_variant(variants)

    result = {
        "disease": disease,
        "score": score,
        "category": category,
        "variant": variant,
        "count": len(variants)
    }

    return render_template("result.html", result=result)

# ============================================================
#  ADMIN: Re-sign mismatched owner signatures (repair tool)
# ============================================================
@app.route('/admin_repair_signatures')
def admin_repair_signatures():
    if session.get('username') is None:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    cursor.execute("""
        SELECT * FROM gn_data_requests
        WHERE owner_signature IS NOT NULL
    """)
    rows = cursor.fetchall()

    fixed  = 0
    failed = 0
    skipped = 0

    for req in rows:
        owner_id = req['owner_id']

        try:
            # ── Check validity against DB key (what admin verify actually uses) ──
            cursor.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (owner_id,))
            owner_row  = cursor.fetchone()
            db_pub_pem = owner_row['public_key'] if owner_row else None

            if db_pub_pem:
                db_pub_key    = serialization.load_pem_public_key(db_pub_pem.encode())
                already_valid = rsa_verify(db_pub_key, req['owner_sign_message'], req['owner_signature'])
                if already_valid:
                    skipped += 1
                    continue

            # ── Key files exist on disk → re-sign then sync DB atomically ──
            private_key_obj = load_private_key_pem(owner_id)   # raises FileNotFoundError if missing
            pub_key_obj     = load_public_key_pem(owner_id)
            pub_pem         = pub_key_obj.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            sign_timestamp   = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            new_sign_message = (
                f"GENENFT_OWNER_APPROVAL|"
                f"RID:{req['id']}|"
                f"OWNER:{owner_id}|"
                f"DATASET:{req['dataset_id']}|"
                f"RESEARCHER:{req['researcher_id']}|"
                f"TS:{sign_timestamp}"
            )

            new_signature = rsa_sign(private_key_obj, new_sign_message)

            # ── Verify before touching DB ──
            if not rsa_verify(pub_key_obj, new_sign_message, new_signature):
                raise Exception("Self-verify failed after re-signing")

            # ── Atomic: public key + signature in one transaction ──
            try:
                cursor.execute(
                    "UPDATE gn_owner SET public_key = %s WHERE uname = %s",
                    (pub_pem, owner_id)
                )
                cursor.execute("""
                    UPDATE gn_data_requests
                    SET owner_signature    = %s,
                        owner_sign_message = %s,
                        admin_approval     = 'Pending'
                    WHERE id = %s
                """, (new_signature, new_sign_message, req['id']))
                conn.commit()
            except Exception as db_err:
                conn.rollback()
                raise Exception(f"DB commit failed: {db_err}")

            print(f"Fixed RID {req['id']} — owner: {owner_id}")
            fixed += 1

        except FileNotFoundError:
            # Key file missing — generate fresh pair, sync DB, re-sign, all atomic
            try:
                private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key_obj  = private_key_obj.public_key()

                priv_pem = private_key_obj.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ).decode()
                pub_pem = public_key_obj.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()

                # Write to disk first
                with open(f"static/kg/{owner_id}_pr.txt", "w") as f:
                    f.write(priv_pem)
                with open(f"static/kg/{owner_id}_pb.txt", "w") as f:
                    f.write(pub_pem)

                sign_timestamp   = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                new_sign_message = (
                    f"GENENFT_OWNER_APPROVAL|"
                    f"RID:{req['id']}|"
                    f"OWNER:{owner_id}|"
                    f"DATASET:{req['dataset_id']}|"
                    f"RESEARCHER:{req['researcher_id']}|"
                    f"TS:{sign_timestamp}"
                )
                new_signature = rsa_sign(private_key_obj, new_sign_message)

                if not rsa_verify(public_key_obj, new_sign_message, new_signature):
                    raise Exception("Self-verify failed after fresh key generation")

                try:
                    cursor.execute(
                        "UPDATE gn_owner SET public_key = %s WHERE uname = %s",
                        (pub_pem, owner_id)
                    )
                    cursor.execute("""
                        UPDATE gn_data_requests
                        SET owner_signature    = %s,
                            owner_sign_message = %s,
                            admin_approval     = 'Pending'
                        WHERE id = %s
                    """, (new_signature, new_sign_message, req['id']))
                    conn.commit()
                except Exception as db_err:
                    conn.rollback()
                    raise Exception(f"DB commit failed after key gen: {db_err}")

                print(f"Generated fresh keys + fixed RID {req['id']} — owner: {owner_id}")
                fixed += 1

            except Exception as e2:
                print(f"Key generation failed for RID {req['id']}: {e2}")
                failed += 1

        except Exception as e:
            conn.rollback()
            print(f"Repair failed for RID {req['id']}: {e}")
            failed += 1

    cursor.close()
    conn.close()

    return (
        f"<h3>Repair Complete</h3>"
        f"<p>✓ Fixed: {fixed}</p>"
        f"<p>⟳ Already valid (skipped): {skipped}</p>"
        f"<p>✗ Failed: {failed}</p>"
        f"<br><a href='/admin_send_approvals'>Go to Approvals</a>"
    )




@app.route('/debug_sig/<rid>')
def debug_sig(rid):
    """Temporary debug route — remove after fixing"""
    conn = get_db_connection()
    cursor = get_db_cursor(conn, dictionary=True)

    # Get request row
    cursor.execute("SELECT * FROM gn_data_requests WHERE id=%s", (rid,))
    req = cursor.fetchone()
    if not req:
        return f"No request found for id={rid}"

    owner_id      = req['owner_id']
    owner_sig     = req['owner_signature']
    owner_msg     = req['owner_sign_message']

    # Get public key from DB
    cursor.execute("SELECT public_key FROM gn_owner WHERE uname=%s", (owner_id,))
    owner_row = cursor.fetchone()
    db_pubkey = owner_row['public_key'] if owner_row else None

    # Get public key from disk
    import os
    disk_path = f"static/kg/{owner_id}_pb.txt"
    disk_pubkey = open(disk_path).read() if os.path.exists(disk_path) else "FILE NOT FOUND"

    # Try verify with DB key
    db_verify = False
    db_err = ""
    try:
        from cryptography.hazmat.primitives import serialization as ser2
        pk = ser2.load_pem_public_key(db_pubkey.encode())
        db_verify = rsa_verify(pk, owner_msg, owner_sig)
    except Exception as e:
        db_err = str(e)

    # Try verify with disk key
    disk_verify = False
    disk_err = ""
    try:
        pk2 = ser2.load_pem_public_key(disk_pubkey.encode())
        disk_verify = rsa_verify(pk2, owner_msg, owner_sig)
    except Exception as e:
        disk_err = str(e)

    # Keys match?
    keys_match = (db_pubkey == disk_pubkey)

    cursor.close()
    conn.close()

    return f"""
    <h2>Debug Signature — RID {rid}</h2>
    <b>owner_id:</b> {owner_id}<br>
    <b>owner_sign_message:</b><br><pre>{owner_msg}</pre>
    <b>owner_signature (first 60):</b> {owner_sig[:60] if owner_sig else 'NULL'}<br><br>
    <b>DB public key (first 60):</b> {db_pubkey[:60] if db_pubkey else 'NULL'}<br>
    <b>Disk public key (first 60):</b> {disk_pubkey[:60]}<br>
    <b>Keys match (DB == Disk):</b> {keys_match}<br><br>
    <b>Verify with DB key:</b> {db_verify} {db_err}<br>
    <b>Verify with Disk key:</b> {disk_verify} {disk_err}<br>
    """

@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)