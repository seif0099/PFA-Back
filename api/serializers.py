from rest_framework import serializers
from .models import *
from django.contrib.auth.hashers import make_password

class SuperAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuperAdmin
        fields = "__all__"
        extra_kwargs = {
            'password': {'write_only': True}
        }


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {
            'password': {'write_only': True}
        }
        


class CompanyAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyAdmin
        fields = "__all__"
        extra_kwargs = {
            'password': {'write_only': True}
        }

class OffreSerializer(serializers.ModelSerializer):
    class Meta:
        model=Offre
        fields = "__all__"


class PostuleOffreSerializer(serializers.ModelSerializer):
    class Meta:
        model=PostuleOffre
        fields = "__all__"