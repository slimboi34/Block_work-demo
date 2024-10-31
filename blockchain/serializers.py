from rest_framework import serializers
from .models import Node, NodeType, Transaction, TxIn, TxOut, Block, DruidDroplet

class NodeTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = NodeType
        fields = '__all__'

class NodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Node
        fields = '__all__'

class TxInSerializer(serializers.ModelSerializer):
    class Meta:
        model = TxIn
        fields = '__all__'

class TxOutSerializer(serializers.ModelSerializer):
    class Meta:
        model = TxOut
        fields = '__all__'

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = '__all__'

class BlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = Block
        fields = '__all__'

class DruidDropletSerializer(serializers.ModelSerializer):
    class Meta:
        model = DruidDroplet
        fields = '__all__'