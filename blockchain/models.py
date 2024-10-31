from django.db import models
from django.contrib.auth.models import User

# Node Types
class NodeType(models.Model):
    TYPE_CHOICES = [
        ('Mempool', 'Mempool Node'),
        ('Miner', 'Miner Node'),
        ('Storage', 'Storage Node'),
    ]
    name = models.CharField(max_length=20, choices=TYPE_CHOICES, unique=True)

class Node(models.Model):
    name = models.CharField(max_length=100)
    node_type = models.ForeignKey(NodeType, on_delete=models.CASCADE)
    active = models.BooleanField(default=True)

# Transaction Structures
class OutPoint(models.Model):
    t_hash = models.CharField(max_length=64)
    n = models.IntegerField()

class TxIn(models.Model):
    previous_out = models.ForeignKey(OutPoint, on_delete=models.CASCADE, null=True)
    script_signature = models.TextField()

class TxOut(models.Model):
    value = models.DecimalField(max_digits=20, decimal_places=8)
    locktime = models.PositiveBigIntegerField()
    drs_block_hash = models.CharField(max_length=64, null=True, blank=True)
    script_public_key = models.CharField(max_length=128, null=True, blank=True)

class Transaction(models.Model):
    inputs = models.ManyToManyField(TxIn)
    outputs = models.ManyToManyField(TxOut)
    version = models.PositiveIntegerField()
    druid_info = models.CharField(max_length=64, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

# Block and Mining Process
class Block(models.Model):
    transactions = models.ManyToManyField(Transaction)
    previous_hash = models.CharField(max_length=64)
    mined_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    proof_of_work = models.CharField(max_length=64)

# DRUID for 2WT
class DruidDroplet(models.Model):
    druid = models.CharField(max_length=64, unique=True)
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE)