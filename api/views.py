from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from rest_framework.response import Response
from .models import *
import jwt,datetime
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import EmailMessage
from .crypt import *
from urllib.parse import urljoin
############################################## -- LOGOUT VIEW -- #########################################

class LogoutView(APIView):
    def post(self,request):
        data=request.data.copy() 
        response=Response(status=status.HTTP_200_OK)
        response.delete_cookie('jwt')
        response.data={
            'message' : 'logout successfully !'
        }
        return response

############################################## -- USER VIEWS -- #########################################

class UserRegisterView(APIView):
    def post(self,request):
        data=request.data.copy() 
        if User.objects.filter(email=data['email']).exists():
            return Response({"message":"User already exist"},status=status.HTTP_400_BAD_REQUEST)
        data['password'] = make_password(data['password'])
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self,request):
        data=request.data.copy() 
        email = data['email']
        password = data['password']

        user = User.objects.filter(email=email).first()
        if user is None:
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(password, user.password):
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        payload = {
            'id':user.id,
            'typeUser':'normal',
            'exp':datetime.datetime.utcnow() + datetime.timedelta(days=3),
            'iat':datetime.datetime.utcnow()
        }
        token = jwt.encode(payload,'sesame_jwt',algorithm='HS256').decode('utf-8')
        
        response= Response(status=status.HTTP_200_OK)
        response.set_cookie(key='jwt',value=token,httponly=True)
        response.data={
            'jwt':token
        }
        return response


class UserView(APIView):
    def get(self,request):
        basePath = "http://127.0.0.1:8000/"
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        
        user=User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        user = serializer.data
        image = serializer.data['image']
        image = urljoin(basePath,image)
        user['image'] = image
        return Response(user,status=status.HTTP_200_OK)

    def put(self,request):
        data=request.data.copy() 
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        user=User.objects.filter(id=payload['id']).first()
        
        try:
            if(data['password']):
                data['password']=make_password(data['password'])
        except:
            pass
        serializer = UserSerializer(user,data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserResetPassView(APIView):
    def post(self, request):
        data=request.data.copy()
        email = data['email']
        user = User.objects.filter(email=email).first()
        if user is None:
            return Response({"message":"User does not exist !"}, status=status.HTTP_400_BAD_REQUEST)
        cryptetId = encrypt_string(str(user.id))
        cryptetId = cryptetId.decode('utf-8')
        email = EmailMessage(
            subject="Reset Password",
            body="You can follow this link to reset your password : http://localhost:3000/user/resetPass?uid={}".format(cryptetId),
            from_email='JOB-BOARD <mohamedamine.khemiri@sesame.com.tn>',
            to=[email],
        )
        try:
            # send the email
            email.send()
        except:
            return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Check your Email !"}, status=status.HTTP_200_OK)
    def patch(self,request):
        data=request.data.copy()
        uid = request.GET.get('uid')
        try:
            uid=uid.encode('utf-8')
            uid=decrypt_string(uid)
        except:
            return Response({"message":"User does not exist !"}, status=status.HTTP_400_BAD_REQUEST)
        user=User.objects.filter(id=uid).first()
        if user is None:
            return Response({"message":"User does not exist !"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if(data['password']):
                data['password']=make_password(data['password'])
        except:
            pass
        serializer = UserSerializer(user,data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Password was changed !"}, status=status.HTTP_200_OK)
        return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)


        


############################################## -- SUPER ADMIN VIEWS -- #########################################

class SuperAdminRegisterView(APIView):
    def post(self,request):
        data=request.data.copy() 
        if SuperAdmin.objects.filter(email=data['email']).exists():
            return Response({"message":"User already exist"},status=status.HTTP_400_BAD_REQUEST)
        data['password'] = make_password(data['password'])
        serializer = SuperAdminSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SuperAdminLoginView(APIView):
    def post(self,request):
        data=request.data.copy() 
        email = data['email']
        password = data['password']

        super_admin = SuperAdmin.objects.filter(email=email).first()
        if super_admin is None:
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(password, super_admin.password):
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        payload = {
            'id':super_admin.id,
            'typeUser':'super',
            'exp':datetime.datetime.utcnow() + datetime.timedelta(days=3),
            'iat':datetime.datetime.utcnow()
        }
        token = jwt.encode(payload,'sesame_jwt',algorithm='HS256').decode('utf-8')
        
        response= Response(status=status.HTTP_200_OK)
        response.set_cookie(key='jwt',value=token,httponly=True)
        response.data={
            'jwt':token
        }
        return response

class SuperAdminView(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        super_admin=SuperAdmin.objects.filter(id=payload['id']).first()
        serializer = SuperAdminSerializer(super_admin)
        return Response(serializer.data,status=status.HTTP_200_OK)

    def put(self,request):
        data=request.data.copy() 
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        super_admin=SuperAdmin.objects.filter(id=payload['id']).first()
        try:
            if(data['password']):
                data['password']=make_password(data['password'])
        except:
            pass
        serializer = SuperAdminSerializer(super_admin,data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SuperAdminGetAllUsersView(APIView):
    def get(self,request):
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_401_UNAUTHORIZED)
        users = User.objects.all()
        serializer = UserSerializer(users,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class SuperAdminGetAllCompaniesView(APIView):
    def get(self,request):
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_401_UNAUTHORIZED)
        companiesAdmins = CompanyAdmin.objects.all()
        serializer = CompanyAdminSerializer(companiesAdmins,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)


class SuperAdminManageUserView(APIView):
    def get(self,request):
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        userId = request.GET.get("id")
        if(User.objects.filter(id=userId).exists()):
            user=User.objects.filter(id=userId).first()
            serializer = UserSerializer(user)
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response({"message":"User Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)
    
    def put(self,request):
        data=request.data.copy() 
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        userId = request.GET.get("id")
        if(User.objects.filter(id=userId).exists()):
            user=User.objects.filter(id=userId).first()
            try:
                if(data['password']):
                    data['password']=make_password(data['password'])
            except:
                pass
            serializer = UserSerializer(user,data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"User Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):
        data=request.data.copy() 
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        userId = request.GET.get("id")
        if(User.objects.filter(id=userId).exists()):
            user=User.objects.filter(id=userId).first()
            user.delete()
            return Response({"message":"User Deleted"},status=status.HTTP_200_OK)
        return Response({"message":"User Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)


class SuperAdminManageCompanyAdminView(APIView):
    def get(self,request):
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        companyAdminId = request.GET.get("id")
        if(CompanyAdmin.objects.filter(id=companyAdminId).exists()):
            company_admin=CompanyAdmin.objects.filter(id=companyAdminId).first()
            serializer = CompanyAdminSerializer(company_admin)
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response({"message":"Company Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)
    
    def put(self,request):
        data=request.data.copy()
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        companyAdminId = request.GET.get("id")
        if(CompanyAdmin.objects.filter(id=companyAdminId).exists()):
            company_admin=CompanyAdmin.objects.filter(id=companyAdminId).first()
            try:
                if(data['password']):
                    data['password']=make_password(data['password'])
            except:
                pass
            serializer = CompanyAdminSerializer(company_admin,data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Company Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):
        data=request.data.copy()
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'super':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        companyAdminId = request.GET.get("id")
        if(CompanyAdmin.objects.filter(id=companyAdminId).exists()):
            company_admin=CompanyAdmin.objects.filter(id=companyAdminId).first()
            company_admin.delete()
            return Response({"message":"User Deleted"},status=status.HTTP_200_OK)
        return Response({"message":"Compnay Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)


############################################## -- COMPANY ADMIN VIEWS -- #########################################


class  CompanyAdminRegisterView(APIView):
    def post(self,request):
        data=request.data.copy() 
        if CompanyAdmin.objects.filter(email=data['email']).exists():
            return Response({"message":"User already exist"},status=status.HTTP_400_BAD_REQUEST)
        data['password'] = make_password(data['password'])
        serializer =  CompanyAdminSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CompanyAdminLoginView(APIView):
    def post(self,request):
        data=request.data.copy()
        email = data['email']
        password = data['password']
        company_admin = CompanyAdmin.objects.filter(email=email).first()
        if company_admin is None:
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(password, company_admin.password):
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        payload = {
            'id':company_admin.id,
            'typeUser':'company',
            'exp':datetime.datetime.utcnow() + datetime.timedelta(days=3),
            'iat':datetime.datetime.utcnow()
        }
        token = jwt.encode(payload,'sesame_jwt',algorithm='HS256').decode('utf-8')
        
        response= Response(status=status.HTTP_200_OK)
        response.set_cookie(key='jwt',value=token,httponly=True)
        response.data={
            'jwt':token
        }
        return response

class CompanyAdminView(APIView):
    def get(self,request):
        basePath = "http://127.0.0.1:8000/"
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        company_admin=CompanyAdmin.objects.filter(id=payload['id']).first()
        serializer = CompanyAdminSerializer(company_admin)
        company = serializer.data
        image = company['image']
        image = urljoin(basePath,image)
        company["image"] = image
        return Response(company,status=status.HTTP_200_OK)

    def put(self,request):
        data=request.data.copy() 
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        company_admin=CompanyAdmin.objects.filter(id=payload['id']).first()
        try:
            if(data['password']):
                data['password']=make_password(data['password'])
        except:
            pass
        serializer = CompanyAdminSerializer(company_admin,data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class CompanyResetPassView(APIView):
    def post(self, request):
        data=request.data.copy()
        email = data['email']
        company = CompanyAdmin.objects.filter(email=email).first()
        if company is None:
            return Response({"message":"Company does not exist !"}, status=status.HTTP_400_BAD_REQUEST)
        cryptetId = encrypt_string(str(company.id))
        cryptetId = cryptetId.decode('utf-8')
        email = EmailMessage(
            subject="Reset Password",
            body="You can follow this link to reset your password : http://localhost:3000/user/resetPass?uid={}".format(cryptetId),
            from_email='JOB-BOARD <mohamedamine.khemiri@sesame.com.tn>',
            to=[email],
        )
        try:
            # send the email
            email.send()
        except:
            return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Check your Email !"}, status=status.HTTP_200_OK)
    def patch(self,request):
        data=request.data.copy()
        uid = request.GET.get('uid')
        try:
            uid=uid.encode('utf-8')
            uid=decrypt_string(uid)
        except:
            return Response({"message":"Company does not exist !"}, status=status.HTTP_400_BAD_REQUEST)
        company=CompanyAdmin.objects.filter(id=uid).first()
        if user is None:
            return Response({"message":"Company does not exist !"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if(data['password']):
                data['password']=make_password(data['password'])
        except:
            pass
        serializer = CompanyAdminSerializer(company,data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Password was changed !"}, status=status.HTTP_200_OK)
        return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)



############################################## -- OFFRE VIEWS -- #########################################
class OffresView(APIView):
    def get(self,request):
        basePath = "http://127.0.0.1:8000/"
        try:
            offres = Offre.objects.all()
            offres = OffreSerializer(offres,many=True).data
            for offre in offres:
                image = CompanyAdmin.objects.filter(id=offre['entreprise']).first()
                image = CompanyAdminSerializer(image).data['image']
                offre['image'] = urljoin(basePath,image)
            return Response(offres,status=status.HTTP_200_OK)
        except:
            return Response({"Message":"Not Found"},status=status.HTTP_400_BAD_REQUEST)

class OffreView(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        basePath = "http://127.0.0.1:8000/"
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        offreId = request.GET.get("id")
        if(Offre.objects.filter(id=offreId).exists()):
            offre=Offre.objects.filter(id=offreId).first()
            serializer = OffreSerializer(offre)
            offre = serializer.data
            image = CompanyAdmin.objects.filter(id=offre['entreprise']).first()
            image = CompanyAdminSerializer(image).data['image']
            offre['image'] = urljoin(basePath,image)
            return Response(offre,status=status.HTTP_200_OK)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def post(self,request):
        data=request.data.copy()
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        data['entreprise']=payload['id']
        serializer = OffreSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self,request):
        data=request.data.copy()
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] not in ['company','super']:
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offreId = request.GET.get("id")
        if(Offre.objects.filter(id=offreId).exists()):
            offre=Offre.objects.filter(id=offreId).first()
            serializer = OffreSerializer(offre,data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)
    def delete(self,request):
        data=request.data.copy()
        token=request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorqithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] not in ['company','super']:
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offreId = request.GET.get("id")
        if(Offre.objects.filter(id=offreId).exists()):
            offre=Offre.objects.filter(id=offreId).first()
            offre.delete()
            return Response({"message":"User Deleted"},status=status.HTTP_200_OK)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)


############################################## -- POSTULE OFFRE VIEWS -- #########################################

class PostuleOffreUserView(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='normal':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        if(PostuleOffre.objects.filter(user=payload["id"]).exists()):
            offresPostule=PostuleOffre.objects.filter(user=payload["id"]).all()
            serializer = PostuleOffreSerializer(offresPostule,many=True)
            offres=[]
            for offre in serializer.data:
                offre1=Offre.objects.filter(id=offre['offre']).first()
                serializerOffres = OffreSerializer(offre1)
                offres.append(serializerOffres.data)
            return Response(offres,status=status.HTTP_200_OK)
        return Response({"message":"User Does Not Have any Offer"},status=status.HTTP_400_BAD_REQUEST)

    def post(self,request):
        data=request.data.copy()
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='normal':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offreId = request.GET.get("id")
        if(PostuleOffre.objects.filter(user=payload["id"],offre=offreId).exists()):
            return Response({"message":"User already applied to this offer"},status=status.HTTP_400_BAD_REQUEST)
        data["user"]=payload["id"]
        data["offre"]=offreId
        serializer = PostuleOffreSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):
        data=request.data.copy()
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='normal':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offrePostuleId = request.GET.get("id")
        if(PostuleOffre.objects.filter(id=offrePostuleId).exists()):
            offrePostule=PostuleOffre.objects.filter(id=offrePostuleId).first()
            offrePostule.delete()
            return Response({"message":"User Deleted"},status=status.HTTP_200_OK)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)


class PostuleOffreCompanyView(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        basePath = "http://127.0.0.1:8000/"
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        if(Offre.objects.filter(entreprise=payload["id"]).exists()):
            offres=Offre.objects.filter(entreprise=payload["id"]).all()
            serializer = OffreSerializer(offres,many=True)
            image = CompanyAdmin.objects.filter(id=payload["id"]).first()
            image = CompanyAdminSerializer(image).data["image"]
            image = urljoin(basePath,image)
            for o in serializer.data:
                o["image"]= image
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response({"message":"Company Does Not Have any Offer"},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request):
        data=request.data.copy()
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offrePostuleId = request.GET.get("id")
        if(PostuleOffre.objects.filter(id=offrePostuleId).exists()):
            offre=PostuleOffre.objects.filter(id=offrePostuleId).first()
            data['etat']=True
            serializer = PostuleOffreSerializer(offre,data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)


#GET ALL POSTULED USERS TO THIS COMPANY OFFERS

class AllPostuledUsersToCompany(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        basePath = "http://127.0.0.1:8000/"
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        companyId = payload['id']
        companyoffers = Offre.objects.filter(entreprise=companyId).all()
        companyOffersSerializer = OffreSerializer(companyoffers,many=True)
        postules = []
        for i in companyOffersSerializer.data:
            if i["postules"]:
                userData = []
                for j in i["postules"]:
                    postuleState = PostuleOffreSerializer(PostuleOffre.objects.filter(offre=i["id"],user=j).first()).data['etat']
                    if postuleState ==False:
                        user = User.objects.filter(id=j).first()
                        user = UserSerializer(user)
                        user=user.data
                        image = user["image"]
                        image = urljoin(basePath, image)
                        user["image"] = image
                        userData.append(user)
                i["postules"] = userData
        data = companyOffersSerializer.data
        data = [i for i in data if i["postules"]]
        return Response(data,status=status.HTTP_200_OK)

class AcceptRefusePost(APIView):
    def patch(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        basePath = "http://127.0.0.1:8000/"
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offreId=request.GET.get("offre")
        userId = request.GET.get("user")
        if(PostuleOffre.objects.filter(offre=offreId,user=userId).exists()):
            userMail = User.objects.filter(id=userId).first()
            userMail = UserSerializer(userMail).data["email"]
            offreName = Offre.objects.filter(id=offreId).first()
            offreName = OffreSerializer(offreName).data['titre']
            company = CompanyAdmin.objects.filter(id=payload['id']).first()
            company = CompanyAdminSerializer(company).data["nomEntreprise"]
            offre=PostuleOffre.objects.filter(offre=offreId,user=userId).first()
            data={
                'etat':True
            }
            serializer = PostuleOffreSerializer(offre,data=data)
            if serializer.is_valid():
                serializer.save()
                email = EmailMessage(
                    subject="Job Application Accepted From {} Company".format(company),
                    body="Thank you for submitting your application To {} job, You are accepted for an interview with us , we will contact you as soon as possible for more details ".format(offreName),
                    from_email='JOB-BOARD <mohamedamine.khemiri@sesame.com.tn>',
                    to=[userMail],
                    )
                try:
                    email.send()

                except:
                    return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        basePath = "http://127.0.0.1:8000/"
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        offreId=request.GET.get("offre")
        userId = request.GET.get("user")
        if(PostuleOffre.objects.filter(offre=offreId,user=userId).exists()):
            userMail = User.objects.filter(id=userId).first()
            userMail = UserSerializer(userMail).data["email"]
            offreName = Offre.objects.filter(id=offreId).first()
            offreName = OffreSerializer(offreName).data['titre']
            company = CompanyAdmin.objects.filter(id=payload['id']).first()
            company = CompanyAdminSerializer(company).data["nomEntreprise"]
            offre=PostuleOffre.objects.filter(offre=offreId,user=userId).first()
            email = EmailMessage(
                subject="Job Application Refused From {} Company".format(company),
                body="Thank you for submitting your application to {} job , we regret to inform you that we will not be proceeding with your application at this time. We wish you success in your future endeavors and hope to have the opportunity to connect with you in the future. ".format(offreName),
                from_email='JOB-BOARD <mohamedamine.khemiri@sesame.com.tn>',
                to=[userMail],
            )
            try:
                email.send()
                print("hello")
                offre.delete()
                return Response({"message":"Done !"}, status=status.HTTP_200_OK)
            except:
                return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"message":"Error Deleting Application"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

class GetUserById(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        basePath = "http://127.0.0.1:8000/"
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] !='company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        id=request.GET.get("id")
        user=User.objects.filter(id=id).first()
        serializer = UserSerializer(user)
        user = serializer.data
        image = urljoin(basePath,user['image'])
        cv = urljoin(basePath,user['cv'])
        cover = urljoin(basePath,user['lettreMotivation'])
        user['image']=image
        user['cv'] = cv
        user['lettreMotivation'] = cover
        return Response(user,status=status.HTTP_200_OK)

        
