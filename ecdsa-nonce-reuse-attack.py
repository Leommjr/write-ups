import ecdsa
import random
import libnum
import hashlib
import sys

# Elliptic Curve Digital Signature Algorithm (ECDSA)
G = ecdsa.NIST256p.generator
order = G.order()
# all operation are in mod order
priv = random.randrange(1,order) #private key
Public_key = ecdsa.ecdsa.Public_key(G, G * priv) #generate pub key
Private_key = ecdsa.ecdsa.Private_key(Public_key, priv) #priv key object
k = random.randrange(1, pow(2,127)) #random nonce
msg="Cachorro"
msg2="Gato"
z = int(hashlib.sha256(msg.encode()).hexdigest(),base=16) 
zlinha = int(hashlib.sha256(msg2.encode()).hexdigest(),base=16) #z'
sig = Private_key.sign(z, k) 
sig2 = Private_key.sign(zlinha, k)
print ("Mensagem1: ",msg)
print ("Sig 1 r,s: ",sig.r,sig.s)
print ("Mensagem2: ",msg2)
print ("Sig 2 r,s: ",sig2.r,sig2.s)
r_inv = libnum.invmod(sig.r, order) #r^-1
s = sig.s
slinha = sig2.s #s'
s_inv = libnum.invmod(s - slinha, order) #s-s'^-1
krecuperado = (((z - zlinha) % order) * s_inv) % order # k
print ("K: ", k)
print ("K recuperado:", krecuperado) 
a = (r_inv * ((krecuperado * s) - z)) % order
print ("\nChave: ",priv)
print ("\nChave encontrada: ",a)
if (ecdsa.ecdsa.Public_key(G, G * a) == Public_key):
  print("\nA chave privada foi recuperada")
  print (a)
