from django.db import models
from datetime import datetime
class UserAbstract(models.Model):
    email = models.CharField(max_length=255,default="")
    password = models.CharField(max_length=255,default="")
    class Meta:
        abstract=True

class SuperAdmin(UserAbstract):
    userName=models.CharField(max_length=255,default="")
    class Meta:
        ordering=['userName']
        db_table='superAdmins'

class User(UserAbstract):
    nom=models.CharField(max_length=255,default="")
    prenom=models.CharField(max_length=255,default="")
    userName=models.CharField(max_length=255,default="")
    image=models.ImageField(upload_to="images/users/",default="")
    adresse=models.CharField(max_length=400,default="")
    age=models.IntegerField(default=0)
    telephone=models.CharField(max_length=25,default="")
    lettreMotivation=models.FileField(upload_to="userLettresMotivation/",default="")
    cv=models.FileField(upload_to="userCv/",default="")
    admin=models.ForeignKey(to=SuperAdmin,on_delete=models.PROTECT,null=True)
    class Meta:
        ordering=['userName']
        db_table='users'

class CompanyAdmin(UserAbstract):
    nomEntreprise=models.CharField(max_length=255,default="")
    description=models.TextField(default="")
    adresse=models.CharField(max_length=255,default="")
    telephone=models.CharField(max_length=25,default="")
    siteWeb=models.CharField(max_length=255,default="")
    codeEntreprise=models.CharField(max_length=255,default="")
    admin=models.ForeignKey(to=SuperAdmin,on_delete=models.PROTECT,null=True)
    class Meta:
        ordering=['nomEntreprise']
        db_table='companyAdmins'

class Offre(models.Model):
    titre=models.CharField(max_length=255,default="")
    description=models.TextField(default="")
    salaire = models.DecimalField(max_digits=10,decimal_places=2,default=0)
    typee = models.CharField(max_length=255,default="")
    Experience = models.IntegerField(default=0)
    adresse=models.CharField(max_length=255,default="")
    deadLine = models.DateField(default=datetime.today().strftime("%Y-%m-%d"))
    entreprise = models.ForeignKey(to=CompanyAdmin,on_delete=models.CASCADE,null=True)
    postules=models.ManyToManyField(to=User,through="PostuleOffre",through_fields=("offre","user"))
    class Meta:
        ordering=['titre']
        db_table='offres'
class PostuleOffre(models.Model):
    user = models.ForeignKey(to=User, on_delete=models.CASCADE,null=True)
    offre = models.ForeignKey(to=Offre, on_delete=models.CASCADE,null=True)
    datePostuler=models.DateField(default=datetime.today().strftime("%Y-%m-%d"))
    etat=models.BooleanField(default=False)
    class Meta:
        ordering=['datePostuler']
        db_table='postuleOffres'



