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
    def create(self, validated_data):
        # Get the uploaded files from validated_data
        image = validated_data.pop('image', None)
        cv = validated_data.pop('cv', None)
        lettre_motivation = validated_data.pop('lettreMotivation', None)

        # Call the superclass create method to create the user instance
        user = super().create(validated_data)

        # Change the name of the uploaded files
        if image:
            image_ext = image.name.split('.')[-1]
            image_name = f"{user.id}.{image_ext}"
            user.image.save(image_name, image)
        if cv:
            cv_ext = cv.name.split('.')[-1]
            cv_name = f"{user.id}.{cv_ext}"
            user.cv.save(cv_name, cv)
        if lettre_motivation:
            lm_ext = lettre_motivation.name.split('.')[-1]
            lm_name = f"{user.id}.{lm_ext}"
            user.lettreMotivation.save(lm_name, lettre_motivation)

        return user
        


class CompanyAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyAdmin
        fields = "__all__"
        extra_kwargs = {
            'password': {'write_only': True}
        }
    def create(self, validated_data):
        # Get the uploaded files from validated_data
        image = validated_data.pop('image', None)

        # Call the superclass create method to create the offre instance
        company = super().create(validated_data)

        # Change the name of the uploaded files
        if image:
            image_ext = image.name.split('.')[-1]
            image_name = f"{company.id}.{image_ext}"
            company.image.save(image_name, image)

        return company

class OffreSerializer(serializers.ModelSerializer):
    class Meta:
        model=Offre
        fields = "__all__"

class PostuleOffreSerializer(serializers.ModelSerializer):
    class Meta:
        model=PostuleOffre
        fields = "__all__"