from django.urls import path
from .views import *
urlpatterns =[
    path("logout",LogoutView.as_view()),
    path("userRegister",UserRegisterView.as_view()),
    path("userLogin",UserLoginView.as_view()),
    path("user",UserView.as_view()),
    path("userRestPass",UserResetPassView.as_view()),
    path("adminRegister",SuperAdminRegisterView.as_view()),
    path("adminLogin",SuperAdminLoginView.as_view()),
    path("admin",SuperAdminView.as_view()),
    path("adminUsers",SuperAdminGetAllUsersView.as_view()),
    path("adminCompanies",SuperAdminGetAllCompaniesView.as_view()),
    path("adminUser",SuperAdminManageUserView.as_view()),
    path("adminCompany",SuperAdminManageCompanyAdminView.as_view()),
    path("companyRegister",CompanyAdminRegisterView.as_view()),
    path("companyLogin",CompanyAdminLoginView.as_view()),
    path("company",CompanyAdminView.as_view()),
    path("companyResetPass",CompanyResetPassView.as_view()),
    path("offres",OffresView.as_view()),
    path("offre",OffreView.as_view()),
    path("postuleOffreUser",PostuleOffreUserView.as_view()),
    path("postuleOffreCompany",PostuleOffreCompanyView.as_view())
]