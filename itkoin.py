from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
from base64 import b64encode, b64decode
from pprint import pprint
import pickle


class ITKoin:
    def __init__ (self):
        self.pending_transactions_filename = 'pending_01.txt'
        self.chain_filename = 'chain_01.txt'
        self.ITKoin_users = ['Antal', 'Béla', 'Cili']  
        self.ICO = 100
        self.chain = []
        self.pending_transactions = []
        self.unspent_outputs = []
        self.payer_unspent_outputs = []

    def create_signature (self, data, signer_privatekey):
        signatureobject = pkcs1_15.new(signer_privatekey) # hozz létre egy signature objektumot
        hashobject = self.create_hashobject(data) # az adatot töltsd be egy hash objektumba a create_hashobject(data) használatával
        signaturevalue = signatureobject.sign(hashobject) # készítsd el az aláírás értéket a sign függvénnyel
        # pprint(signaturevalue)
        b64signaturevalue = b64encode(signaturevalue) # kódold base64 kódolással
        # pprint(b64signaturevalue)
        # pprint(b64signaturevalue.decode())
        return b64signaturevalue.decode()

    def verify_signature(self, data, b64signaturevalue, rsapublickey):
        verifyobject = pkcs1_15.new(rsapublickey) # hozz létre egy verify objektumot
        hashobject = self.create_hashobject(data) # az adatot töltsd be egy hash objektumba a create_hashobject(data) használatával
        signaturevalue = b64decode(b64signaturevalue.encode()) # dekódold base64 kódolással az aláírás értéket
        signatureerror = verifyobject.verify(hashobject, signaturevalue) # ellenőrizd az aláírást
        validsignature = not signatureerror # értéke: True, ha az aláírás érvényes
        return validsignature

    @staticmethod
    def create_hashobject (data):
        stringdump = json.dumps(data)
        hashobject = SHA256.new(stringdump.encode())
        return hashobject

    @staticmethod
    def create_hashhexvalue (data):
        stringdump = json.dumps(data)
        hashobject = SHA256.new(stringdump.encode())
        return hashobject.hexdigest()

    @staticmethod
    def save_list(list, filename):
        f = open(filename, 'wb')
        pickle.dump(list, f)
        f.close()
        return

    def create_users(self):
        for user in self.ITKoin_users:
            self.generate_rsa_key(user)
        return

    def generate_rsa_key(self, username): # a username lesz a filenév töve és három file-t generál: a privát és publikus kulcsoknak, ill. az ID-nak
        key = RSA.generate(2048)
        publickey = key.publickey()
        privatekey_filename = username + '_priv.pem'
        f = open(privatekey_filename, 'wb')
        f.write(key.export_key())
        f.close()
        publickey_filename = username + '_pub.pem'
        f = open(publickey_filename, 'wb')
        f.write(publickey.export_key())
        f.close()
        publickey_string = publickey.export_key().decode('ascii') # bináris stringet karakter stringgé konvertáljuk, hogy a json.dumps működjön rajta
        recipient_id_filename = username + '_id.txt'
        f = open(recipient_id_filename, 'wb')
        f.write(self.create_hashhexvalue(publickey_string).encode('ascii')) # a hexa string hash értéket bináris stringgé konvertáljuk a file-ba íráshoz
        f.close()
        return

    @staticmethod
    def load_privatekey (username):
        privatekey_filename = username + '_priv.pem'
        fileobject = open(privatekey_filename, 'r')
        user_privatekey = RSA.import_key(fileobject.read())
        #pprint(user_privatekey)
        return user_privatekey

    @staticmethod
    def load_publickey (username):
        publickey_filename = username + '_pub.pem'
        fileobject = open(publickey_filename, 'r')
        user_publickey = RSA.import_key(fileobject.read())
        #pprint(user_publickey)
        return user_publickey

    @staticmethod
    def load_publickeyfromprivatekey (username):
        privatekey_filename = username + '_priv.pem'
        fileobject = open(privatekey_filename, 'r')
        user_privatekey = RSA.import_key(fileobject.read())
        user_publickey = user_privatekey.publickey()
        #pprint(user_publickey)
        return user_publickey

    @staticmethod
    def load_id (username):
        id_filename = username + '_id.txt'
        fileobject = open(id_filename, 'r')
        user_id = fileobject.read()
        #pprint(user_id)
        return user_id

    def load_chain(self):
        fileobject = open(self.chain_filename, 'rb')
        self.chain = pickle.load(fileobject)
        #pprint(self.chain)
        previous_block_header_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        #######################BLOKKLÁNC ÉRVÉNYESSÉG ELLENÖRZÉS##############################################
        for block in self.chain:
          if self.create_hashhexvalue(block['transactions']) != block['block_header']['transactions_hash']: #a vizsgált blokk tranzakcióinak hashlenyomata megegyezik-e a blokkheaderben lévő lenyomattal
            return False
          if self.create_hashhexvalue(block['block_header'])[:4] != "0000": #blokk header a vezető nullákkal kezdődik-e
            return False

          if previous_block_header_hash != block['block_header']['previous_block_header_hash']: #a láncolt lista hivatkozás helyes-e a korábbi blokk esetén
            return False
          else:
            previous_block_header_hash = self.create_hashhexvalue(block['block_header']) # ha igen akkor léptetem a változót a jelenlegi blokkra.
        #######################BLOKKLÁNC ÉRVÉNYESSÉG ELLENÖRZÉS##############################################

        return True

    def load_pending_transactions(self):
        fileobject = open(self.pending_transactions_filename, 'rb')
        self.pending_transactions = pickle.load(fileobject)
        validated_pending_transactions = []
        while len(self.pending_transactions) != 0:
            transaction = self.pending_transactions.pop()
            #############tranzakció ellenörzés######################

            #ha az outputok összege és az inputok összege megegyezik akkor ez a feltétel telejesül: sum_out-sum_in == 0
            for output in transaction['outputs']:
              sum_out += output['csaposhi']
            for input in transaction['inputs']:
              sum_in += input['csaposhi']
            
            if (sum_in - sum_out) == 0:


              
              # input[4] a publikus kulcsom PEM formátumban
              publickey_string = transaction['inputs'][0][4] #a tranzakció első inputjának publikus kulcsa
              p_id = self.create_hashhexvalue(publickey_string).encode('ascii') # a küldő id-ja szükséges az unspent outputs leválogatáshoz
              self.find_unspent_outputs(p_id)




              for input in transaction['inputs']: #megnézzük el volt-e költve már az input 
              
                for block in self.chain:
                  for block_transaction in block['transactions']:
                      for used_input in block_transaction['inputs']:
                          if input == used_input: # ha az input mar szerepelt a felhasznalt inputok kozott
                              doublespend = True #már egyszer elköltötte --> doublespend
                              break

                if not self.verify_signature(input[0], input[3], RSA.import_key(input[4])):
                  badsignature = True # ha  Az inputban szereplő aláírás a publikus kulccsal nem érvényes aláírásellenőrzést eredményez eldobjuk a tranzakciót.
                  break

                for block in self.chain:
                  for transaction_ in block['transactions']:
                    if input[0] == transaction_['txid']:
                      if transaction_['outputs'][input[1]]['recipient'] != self.create_hashhexvalue(input[4]).encode('ascii'):
                        unauthorizedspend = True # ha  Az inputban szereplő publikus kulcs lenyomata nem egyezik meg a felhasznált outputban megjelölt címzett azonosítóval eldobjuk
                        break 
                  
              if doublespend or badsignature or unauthorizedspend:
                continue # ha valamelyik fenti probléma van a tranzakcióval akkor eldobjuk.
              else: #helyes tranzakció elfogadjuk
                validated_pending_transactions.append(transaction)




            else:#ha nem egyezik az input-output összeg akkor eldobjuk a tranzakciot
              continue
            #############tranzakció ellenörzés######################
        self.pending_transactions = validated_pending_transactions
        #pprint(self.pending_transactions)
        return

    def find_unspent_outputs(self, payer):
        payer_id = self.load_id (payer)
        self.unspent_outputs = []
        self.payer_unspent_outputs = []
        for block in self.chain:
            for transaction in block['transactions']:
                for output in transaction['outputs']:
                    self.unspent_outputs.append([transaction['txid'], transaction['outputs'].index(output), output['csaposhi']])
                    if output['recipient'] == payer_id:
                        self.payer_unspent_outputs.append([transaction['txid'], transaction['outputs'].index(output), output['csaposhi']])
                for input in transaction['inputs']:
                    spent_output = [input[0], input[1], input[2]] # A remove() hibát dob, ha úgy törlünk a listából valamit, hogy nem is volt benne,
                    # ezért az input-ból ki kell hagyni azokat az elemeket, amiket az unspent_outputba nem tettünk bele (aláírás érték és publikus kulcs) 
                    pprint(spent_output)
                    self.unspent_outputs.remove(spent_output) # minden input biztosan szerepelt a lánc korábbi outputjaként
                    if spent_output in self.payer_unspent_outputs:
                        self.payer_unspent_outputs.remove(spent_output)
        pprint(self.unspent_outputs)
        pprint(self.payer_unspent_outputs)
        return

    def mine(self, miner):
        if len(self.chain) == 0:
            previous_block_header_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        else:
            previous_block = self.chain[-1]
            previous_block_header = previous_block['block_header']
            previous_block_header_hash = self.create_hashhexvalue(previous_block_header)

        nonce = 0
        reward = self.reward_transaction(500, miner)
        self.pending_transactions.append(reward)
        # pprint(self.pending_transactions)
        
        block_header = {
            'nonce': nonce,
            'previous_block_header_hash': previous_block_header_hash,
            'transactions_hash' : self.create_hashhexvalue(self.pending_transactions),
        }

        while True:
            block_header_hash = self.create_hashhexvalue(block_header)
            if block_header_hash[:4] == "0000":
                break
            block_header['nonce'] += 1
        # pprint (block_header_hash)

        block = {
            'block_header': block_header,
            'transactions': self.pending_transactions
        }
        
        pprint(block)
        self.chain.append(block)
        # pprint (self.chain)
        self.save_list(self.chain, self.chain_filename)
        self.pending_transactions = [] # Ki kell üríteni a tranzakciós listát, mert bekerültek a blokkba
        self.save_list(self.pending_transactions, self.pending_transactions_filename)
        return

    def generate_first_block(self, miner):
        self.chain = [] # Üres lánccal indulunk
        self.pending_transactions = [] # És üres tranzakció listával
        while len(self.ITKoin_users) > 0:
            recipient_id = self.load_id (self.ITKoin_users.pop()) # előveszi a következő id file nevét és beolvassa az id-t
            for tr in self.pending_transactions: # nem szerepelhet kétszer ugyanaz a recipient, mert akkor a txid azonos lesz
                for op in tr['outputs']:
                    if recipient_id == op['recipient']:
                        pprint ('HIBA: Ismétlődő recipient adatok az első blokk generálásakor.')
                        return False
            self.ICO_transaction(self.ICO, recipient_id)
            #pprint(self.pending_transactions)
        self.mine(miner)
        return

    def payment_transaction(self, csaposhi, payer, recipient): # A megadott csaposhi összeg átadása payertől recipientnek és a tranzakció lista bővítése
        payer_id = self.load_id (payer)
        recipient_id = self.load_id (recipient)
        self.find_unspent_outputs(payer)
        sum = 0
        used_outputs=[]
        while (sum < csaposhi):
            next_output=self.payer_unspent_outputs.pop()
            used_outputs.append(next_output)
            sum += next_output[2] # ebben a listapozícióban van a hivatkozott outputban kapott összeg
        inputs = used_outputs
        # Az inputok felhasználási jogának igazolása a felhasználó aláírásával:
        payer_privatekey = self.load_privatekey(payer)
        payer_publickey = self.load_publickeyfromprivatekey(payer)
        for input in inputs: # az inputsban szándékosan nincs benne az akkori recipient, mert ezt abból a tranzakcióból kell majd kivenni és ellenőrizni
            input.append(self.create_signature(input[0], payer_privatekey)) # input[3] az aláírás érték base64 kódolással
            input.append(payer_publickey.export_key().decode('ascii')) # input[4] a publikus kulcsom PEM formátumban
            pprint(input)
            pprint(RSA.import_key(input[4]))
            pprint(self.verify_signature(input[0], input[3], RSA.import_key(input[4])))
        outputs = [{
            'csaposhi': csaposhi,
            'recipient': recipient_id}]
        if sum > csaposhi: # ha van visszajáró, azt visszautaljuk magunknak
            outputs.append({
                'csaposhi': sum-csaposhi,
                'recipient': payer_id})
        transaction = {
            'inputs': inputs,
            'outputs': outputs}
        transaction ['txid'] = self.create_hashhexvalue(transaction) # a tranzakció lenyomata lesz az azonosítója egyben
        self.pending_transactions.append(transaction)
        pprint(self.pending_transactions)
        return

    def reward_transaction(self, reward, miner): # A bányászjutalom létrehozása a bányásznak: input nélküli output.
        miner_id = self.load_id (miner)
        inputs = []
        outputs = [{
            'csaposhi': reward,
            'recipient': miner_id}]
        transaction = {
            'inputs': inputs,
            'outputs': outputs}
        transaction ['txid'] = self.create_hashhexvalue(transaction) # a tranzakció lenyomata lesz az azonosítója egyben
        return transaction

    def ICO_transaction(self, ICO, recipient): # Initial Coin Offering kifizetése a résztvevőknek: Input nélküli output
        inputs = []
        outputs = [{
            'csaposhi': ICO,
            'recipient': recipient}]
        transaction = {
            'inputs': inputs,
            'outputs': outputs}
        transaction ['txid'] = self.create_hashhexvalue(transaction) # a tranzakció lenyomata lesz az azonosítója egyben
        self.pending_transactions.append(transaction)
        #pprint(self.pending_transactions)
        return
