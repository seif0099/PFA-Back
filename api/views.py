from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from rest_framework.response import Response
from .models import *
import jwt,datetime
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import EmailMessage
from .crypt import *
############################################## -- LOGOUT VIEW -- #########################################

class LogoutView(APIView):
    def post(self,request):
        response=Response(status=status.HTTP_200_OK)
        response.delete_cookie('jwt')
        response.data={
            'message' : 'logout successfully !'
        }
        return response

############################################## -- USER VIEWS -- #########################################

class UserRegisterView(APIView):
    def post(self,request):
        if User.objects.filter(email=request.data['email']).exists():
            return Response({"message":"User already exist"},status=status.HTTP_400_BAD_REQUEST)
        request.data['password'] = make_password(request.data['password'])
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self,request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()
        if user is None:
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(password, user.password):
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        payload = {
            'id':user.id,
            'typeUser':'normal',
            'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
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
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        user=User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data,status=status.HTTP_200_OK)

    def put(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        user=User.objects.filter(id=payload['id']).first()
        try:
            if(request.data['password']):
                request.data['password']=make_password(request.data['password'])
        except:
            pass
        serializer = UserSerializer(user,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserResetPassView(APIView):
    def post(self, request):
        email = request.data['email']
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
            if(request.data['password']):
                request.data['password']=make_password(request.data['password'])
        except:
            pass
        serializer = UserSerializer(user,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Password was changed !"}, status=status.HTTP_200_OK)
        return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)


        


############################################## -- SUPER ADMIN VIEWS -- #########################################

class SuperAdminRegisterView(APIView):
    def post(self,request):
        if SuperAdmin.objects.filter(email=request.data['email']).exists():
            return Response({"message":"User already exist"},status=status.HTTP_400_BAD_REQUEST)
        request.data['password'] = make_password(request.data['password'])
        serializer = SuperAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SuperAdminLoginView(APIView):
    def post(self,request):
        email = request.data['email']
        password = request.data['password']

        super_admin = SuperAdmin.objects.filter(email=email).first()
        if super_admin is None:
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(password, super_admin.password):
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        payload = {
            'id':super_admin.id,
            'typeUser':'super',
            'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
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
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        super_admin=SuperAdmin.objects.filter(id=payload['id']).first()
        try:
            if(request.data['password']):
                request.data['password']=make_password(request.data['password'])
        except:
            pass
        serializer = SuperAdminSerializer(super_admin,data=request.data)
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
                if(request.data['password']):
                    request.data['password']=make_password(request.data['password'])
            except:
                pass
            serializer = UserSerializer(user,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"User Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):
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
                if(request.data['password']):
                    request.data['password']=make_password(request.data['password'])
            except:
                pass
            serializer = CompanyAdminSerializer(company_admin,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Company Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):
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
        if CompanyAdmin.objects.filter(email=request.data['email']).exists():
            return Response({"message":"User already exist"},status=status.HTTP_400_BAD_REQUEST)
        request.data['password'] = make_password(request.data['password'])
        serializer =  CompanyAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CompanyAdminLoginView(APIView):
    def post(self,request):
        email = request.data['email']
        password = request.data['password']

        company_admin = CompanyAdmin.objects.filter(email=email).first()
        if company_admin is None:
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(password, company_admin.password):
            return Response({"message":"Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)
        payload = {
            'id':company_admin.id,
            'typeUser':'company',
            'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
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
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        company_admin=CompanyAdmin.objects.filter(id=payload['id']).first()
        serializer = CompanyAdminSerializer(company_admin)
        return Response(serializer.data,status=status.HTTP_200_OK)

    def put(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        company_admin=CompanyAdmin.objects.filter(id=payload['id']).first()
        try:
            if(request.data['password']):
                request.data['password']=make_password(request.data['password'])
        except:
            pass
        serializer = CompanyAdminSerializer(company_admin,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class CompanyResetPassView(APIView):
    def post(self, request):
        email = request.data['email']
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
            if(request.data['password']):
                request.data['password']=make_password(request.data['password'])
        except:
            pass
        serializer = CompanyAdminSerializer(company,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Password was changed !"}, status=status.HTTP_200_OK)
        return Response({"message":"Try later !"}, status=status.HTTP_400_BAD_REQUEST)



############################################## -- OFFRE VIEWS -- #########################################
class OffresView(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        offres = Offre.objects.all()
        serializer = OffreSerializer(offres,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class OffreView(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
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
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)

    def post(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token,'sesame_jwt',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({"message":"Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload['typeUser'] != 'company':
            return Response({"message":"Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        request.data['entreprise']=payload['id']
        serializer = OffreSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self,request):
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
            serializer = OffreSerializer(offre,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)
    def delete(self,request):
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
        request.data["user"]=payload["id"]
        request.data["offre"]=offreId
        serializer = PostuleOffreSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request):
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
            
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response({"message":"User Does Not Have any Offer"},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request):
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
            request.data['etat']=True
            serializer = PostuleOffreSerializer(offre,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"Offre Does Not Exist"},status=status.HTTP_400_BAD_REQUEST)