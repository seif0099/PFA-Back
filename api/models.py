from django.db import models
from datetime import datetime
from django.utils import timezone
class UserAbstract(models.Model):
    email = models.CharField(max_length=255,default="",null=True)
    password = models.CharField(max_length=255,default="",null=True)
    class Meta:
        abstract=True

class SuperAdmin(UserAbstract):
    userName=models.CharField(max_length=255,default="",null=True)
    class Meta:
        ordering=['userName']
        db_table='superAdmins'

class User(UserAbstract):
    nom=models.CharField(max_length=255,default="",null=True)
    prenom=models.CharField(max_length=255,default="",null=True)
    userName=models.CharField(max_length=255,default="",null=True)
    image=models.ImageField(upload_to="images/users/",default="",null=True)
    adresse=models.CharField(max_length=400,default="",null=True)
    age=models.IntegerField(default=0,null=True)
    telephone=models.CharField(max_length=25,default="",null=True)
    lettreMotivation=models.FileField(upload_to="userLettresMotivation/",default="",null=True)
    cv=models.FileField(upload_to="userCv/",default="",null=True)
    admin=models.ForeignKey(to=SuperAdmin,on_delete=models.PROTECT,null=True)
    class Meta:
        ordering=['userName']
        db_table='users'

class CompanyAdmin(UserAbstract):
    nomEntreprise=models.CharField(max_length=255,default="",null=True)
    description=models.TextField(default="",null=True)
    adresse=models.CharField(max_length=255,default="",null=True)
    telephone=models.CharField(max_length=25,default="",null=True)
    siteWeb=models.CharField(max_length=255,default="",null=True)
    codeEntreprise=models.CharField(max_length=255,default="",null=True)
    image = models.ImageField(upload_to="images/company/",default="",null=True)
    admin=models.ForeignKey(to=SuperAdmin,on_delete=models.PROTECT,null=True)
    class Meta:
        ordering=['nomEntreprise']
        db_table='companyAdmins'

class Offre(models.Model):
    titre=models.CharField(max_length=255,default="",null=True)
    description=models.TextField(default="",null=True)
    salaire = models.DecimalField(max_digits=10,decimal_places=2,default=0,null=True)
    typee = models.CharField(max_length=255,default="",null=True)
    experience = models.IntegerField(default=0,null=True)
    adresse=models.CharField(max_length=255,default="",null=True)
    deadLine = models.DateField(default=datetime.today().strftime("%Y-%m-%d"),null=True)
    entreprise = models.ForeignKey(to=CompanyAdmin,on_delete=models.CASCADE,null=True)
    postules=models.ManyToManyField(to=User,through="PostuleOffre",through_fields=("offre","user"),null=True)
    class Meta:
        ordering=['titre']
        db_table='offres'
class PostuleOffre(models.Model):
    user = models.ForeignKey(to=User, on_delete=models.CASCADE,null=True)
    offre = models.ForeignKey(to=Offre, on_delete=models.CASCADE,null=True)
    datePostuler=models.DateField(default=datetime.today().strftime("%Y-%m-%d"),null=True)
    etat=models.BooleanField(default=False)
    class Meta:
        ordering=['datePostuler']
        db_table='postuleOffres'



