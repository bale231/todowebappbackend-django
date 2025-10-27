## All external import django
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.db.models.functions import Lower
from django.db.models import Q
from .models import Todo, Category, Profile, Notification, FriendRequest, Friendship, ListCategory, SharedList, SharedCategory
from .serializers import EmailOrUsernameTokenObtainPairSerializer, UserProfileSerializer, FriendRequestSerializer, FriendshipSerializer


# Rest-Framework
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated

## Date/Time package
from datetime import datetime, timedelta

## Import module
import logging
import json
logger = logging.getLogger(__name__)

## Function for unauthorized
def unauthorized(request):
    return JsonResponse({'message': 'Unauthorized'}, status=401)


class EmailOrUsernameTokenView(TokenObtainPairView):
    serializer_class = EmailOrUsernameTokenObtainPairSerializer

## VIEW MOBILE LOGIN
@method_decorator(csrf_exempt, name='dispatch')
class MobileLoginView(View):
    def post(self, request):
        if request.content_type and "application/json" in request.content_type:
            try:
                payload = json.loads(request.body.decode() or "{}")
            except json.JSONDecodeError:
                payload = {}
            identifier = payload.get("username") or payload.get("email")
            password   = payload.get("password")
        else:
            identifier = request.POST.get("username") or request.POST.get("email")
            password   = request.POST.get("password")

        if not identifier or not password:
            return HttpResponse("Dati non validi", status=400)

        user_obj = User.objects.filter(username__iexact=identifier).first()
        if user_obj is None and "@" in identifier:
            user_obj = User.objects.filter(email__iexact=identifier).first()

        if not user_obj:
            return HttpResponse("Credenziali errate o utente non trovato", status=401)

        user = authenticate(request, username=user_obj.username, password=password)
        if user is None:
            return HttpResponse("Credenziali errate o utente non trovato", status=401)

        refresh = RefreshToken.for_user(user)
        return JsonResponse({
            "message": "login ok",
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        })

## VIEW CURRENT USER JWT
class JWTCurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            profile = Profile.objects.get(user=user)
            theme = profile.theme
            push_enabled = profile.push_notifications_enabled
        except Profile.DoesNotExist:
            theme = "light"
            push_enabled = True

        return Response({
            "username": user.username,
            "email": user.email,
            "id": user.id,
            'profile_picture': profile.profile_picture.url if profile and profile.profile_picture else None,
            "theme": theme,
            "push_notifications_enabled": push_enabled,
        })

## VIEW LOGIN
import logging

logger = logging.getLogger("login")

class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def post(self, request):
        data = request.data or {}
        identifier = (data.get("username") or data.get("email") or "").strip()
        password = (data.get("password") or "")
        remember_me = data.get("remember_me", False)  # Nuovo campo

        logger.info("[LOGIN] ct=%s keys=%s ident='%s' remember_me=%s",
                    request.content_type, list(data.keys()), identifier, remember_me)

        if not identifier or not password:
            return Response({"message": "Missing credentials"}, status=400)

        candidates = []
        if "@" in identifier:
            candidates = list(User.objects.filter(email__iexact=identifier))
            if not candidates:
                u = User.objects.filter(username__iexact=identifier).first()
                if u: candidates = [u]
        else:
            u = User.objects.filter(username__iexact=identifier).first()
            if u:
                candidates = [u]
            else:
                candidates = list(User.objects.filter(email__iexact=identifier))

        user = None
        for u in candidates:
            user = authenticate(username=u.username, password=password)
            if user:
                break

        if user is None:
            return Response({"message": "Invalid credentials"}, status=401)

        if not user.is_active:
            return Response({"message": "email not verified"}, status=403)

        # Crea token con durata basata su remember_me
        refresh = RefreshToken.for_user(user)

        if remember_me:
            # Token lunghi se "rimani connesso"
            refresh.set_exp(lifetime=timedelta(days=30))
            refresh.access_token.set_exp(lifetime=timedelta(days=7))

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {"id": user.id, "username": user.username, "email": user.email},
            "remember_me": remember_me  # Restituisci il flag per il frontend
        })

## VIEW LOGOUT
class LogoutView(View):
    def post(self, request):
        from django.contrib.auth import logout
        logout(request)
        return JsonResponse({'message': 'logout success'})

# VIEW REGISTER
@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return JsonResponse({"error": "Missing fields"}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({"error": "Username già esistente"}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({"error": "Email già registrata"}, status=400)

        # ✅ Crea utente non attivo
        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            is_active=True,
        )

        # ✅ Invia email di verifica
        # uid = urlsafe_base64_encode(force_bytes(user.pk))
        # token = default_token_generator.make_token(user)

        # verify_url = f"https://todowebapp-frontend-reactts-stml.vercel.app/verify-email/{uid}/{token}"

        # context = {
        #    "title": "Verifica la tua email",
        #    "message": "Clicca il pulsante in basso per confermare la tua email.",
        #    "action_text": "Conferma email",
        #    "action_url": verify_url,
        #    "year": datetime.now().year,
        # }

        # html_content = render_to_string("emails/email_verifica.html", context)
        # print("✅ Email di verifica sarebbe stata inviata a:", user.email)

        # if not send_verification_email(user.email, "Verifica la tua email", html_content):
        #    return JsonResponse({"error": "Registrazione ok, ma errore invio email"}, status=500)

        return JsonResponse({"message": "register success"})

## VIEW DELETE ACCOUNT
class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "Account disattivato"})

## VIEW SEND EMAIL VERIFICATION
class SendEmailVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        verify_url = f"https://todowebapp-frontend-reactts-stml.vercel.app/verify-email/{uid}/{token}"

        context = {
            "title": "Verifica la tua email",
            "message": "Clicca il pulsante in basso per confermare la tua email.",
            "action_text": "Conferma email",
            "action_url": verify_url,
            "year": datetime.now().year,
        }

        html_content = render_to_string("emails/email_verifica.html", context)

        send_mail(
            subject="Verifica la tua email",
            message="Clicca sul link per verificare la tua email.",
            from_email='"ToDoWebApp Bale" <todoapp@webdesign-vito-luigi.it>',
            recipient_list=[user.email],
            html_message=html_content,
        )
        return Response({"message": "Verification email sent"})

## VIEW CONFIRM EMAIL
class ConfirmEmailView(View):
    def get(self, request, uidb64, token):
        try:
            uid_decoded = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid_decoded)
        except (User.DoesNotExist, ValueError, TypeError):
            return JsonResponse({"verified": False}, status=400)

        if user.is_active:
            return JsonResponse({"verified": True})

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return JsonResponse({"verified": True})

        return JsonResponse({"verified": False}, status=400)

### VIEW TODOS

## VIEW GET ALL CATEGORIES

## VIEW GET ALL LIST CATEGORIES
class ListCategoryListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Lista tutte le categorie dell'utente e quelle condivise"""
        # Categorie di proprietà dell'utente
        categories = ListCategory.objects.filter(user=request.user)

        # Categorie condivise con l'utente
        shared_categories = SharedCategory.objects.filter(shared_with=request.user).select_related('category')

        data = []

        # Aggiungi le categorie di proprietà
        for cat in categories:
            data.append({
                "id": cat.id,
                "name": cat.name,
                "is_owner": True,
                "is_shared": False,
                "can_edit": True,
                "shared_by": None
            })

        # Aggiungi le categorie condivise
        for shared in shared_categories:
            cat = shared.category
            data.append({
                "id": cat.id,
                "name": cat.name,
                "is_owner": False,
                "is_shared": True,
                "can_edit": shared.can_edit,
                "shared_by": {
                    "id": shared.shared_by.id,
                    "username": shared.shared_by.username,
                    "full_name": shared.shared_by.profile.get_full_name() if hasattr(shared.shared_by, 'profile') else shared.shared_by.username
                }
            })

        return Response(data)

    def post(self, request):
        """Crea una nuova categoria"""
        name = request.data.get("name", "").strip()

        if not name:
            return Response({"error": "Nome richiesto"}, status=400)

        # Controlla duplicati
        if ListCategory.objects.filter(user=request.user, name=name).exists():
            return Response({"error": "Categoria già esistente"}, status=400)

        category = ListCategory.objects.create(user=request.user, name=name)
        return Response({"id": category.id, "name": category.name})


## VIEW DETAIL/UPDATE/DELETE SINGLE CATEGORY
class ListCategoryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        """Modifica il nome di una categoria"""
        name = request.data.get("name", "").strip()

        if not name:
            return Response({"error": "Nome richiesto"}, status=400)

        try:
            category = ListCategory.objects.get(id=pk, user=request.user)
            category.name = name
            category.save()
            return Response({"id": category.id, "name": category.name})
        except ListCategory.DoesNotExist:
            return Response({"error": "Categoria non trovata"}, status=404)

    def delete(self, request, pk):
        """Elimina una categoria"""
        try:
            category = ListCategory.objects.get(id=pk, user=request.user)
            category.delete()
            return Response({"message": "Categoria eliminata"})
        except ListCategory.DoesNotExist:
            return Response({"error": "Categoria non trovata"}, status=404)

## VIEW PER SALVARE/RECUPERARE PREFERENZA ORDINE CATEGORIE
class CategorySortPreferenceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Recupera la preferenza ordine alfabetico categorie"""
        profile, created = Profile.objects.get_or_create(user=request.user)
        return Response({"category_sort_alpha": profile.category_sort_alpha})

    def patch(self, request):
        """Salva la preferenza ordine alfabetico categorie"""
        profile, created = Profile.objects.get_or_create(user=request.user)
        category_sort_alpha = request.data.get("category_sort_alpha", False)
        profile.category_sort_alpha = category_sort_alpha
        profile.save()
        return Response({"category_sort_alpha": profile.category_sort_alpha})

## VIEW PER GESTIRE LA CATEGORIA SELEZIONATA
class SelectedCategoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Recupera la categoria selezionata dall'utente"""
        profile, created = Profile.objects.get_or_create(user=request.user)
        selected_category_id = profile.selected_category.id if profile.selected_category else None
        return Response({"selected_category": selected_category_id})

    def patch(self, request):
        """Salva la categoria selezionata dall'utente"""
        profile, created = Profile.objects.get_or_create(user=request.user)
        category_id = request.data.get("selected_category")

        if category_id is None:
            profile.selected_category = None
        else:
            try:
                category = ListCategory.objects.get(id=category_id, user=request.user)
                profile.selected_category = category
            except ListCategory.DoesNotExist:
                return Response({"error": "Categoria non trovata"}, status=404)

        profile.save()
        selected_category_id = profile.selected_category.id if profile.selected_category else None
        return Response({"selected_category": selected_category_id})

class CategoryListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Liste di proprietà dell'utente
        categories = Category.objects.filter(user=user)

        # Liste condivise con l'utente
        shared_lists = SharedList.objects.filter(shared_with=user).select_related('list')

        data = []

        # Aggiungi le liste di proprietà dell'utente
        for cat in categories:
            sort_order = getattr(cat, 'sort_order', 'created') or 'created'

            if sort_order == "alphabetical":
                todos = cat.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by(Lower('title'))
            elif sort_order == "completed":
                todos = cat.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by('completed', '-id')
            else:
                todos = cat.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by('-id')

            category_data = None
            if cat.category:
                category_data = {"id": cat.category.id, "name": cat.category.name}

            # Costruisci lista todos con created_by e modified_by
            todos_list = []
            for t in todos:
                todo_data = {
                    "id": t.id,
                    "title": t.title,
                    "completed": t.completed
                }
                if t.created_by:
                    todo_data["created_by"] = {
                        "id": t.created_by.id,
                        "username": t.created_by.username,
                        "full_name": t.created_by.profile.get_full_name() if hasattr(t.created_by, 'profile') else t.created_by.username
                    }
                else:
                    todo_data["created_by"] = None

                if t.modified_by:
                    todo_data["modified_by"] = {
                        "id": t.modified_by.id,
                        "username": t.modified_by.username,
                        "full_name": t.modified_by.profile.get_full_name() if hasattr(t.modified_by, 'profile') else t.modified_by.username
                    }
                else:
                    todo_data["modified_by"] = None

                todos_list.append(todo_data)

            data.append({
                "id": cat.id,
                "name": cat.name,
                "color": getattr(cat, "color", "blue"),
                "created_at": getattr(cat, "created_at", ""),
                "sort_order": sort_order,
                "category": category_data,
                "is_owner": True,
                "is_shared": False,
                "can_edit": True,
                "shared_by": None,
                "todos": todos_list
            })

        # Aggiungi le liste condivise con l'utente
        for shared in shared_lists:
            cat = shared.list
            sort_order = getattr(cat, 'sort_order', 'created') or 'created'

            if sort_order == "alphabetical":
                todos = cat.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by(Lower('title'))
            elif sort_order == "completed":
                todos = cat.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by('completed', '-id')
            else:
                todos = cat.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by('-id')

            category_data = None
            if cat.category:
                category_data = {"id": cat.category.id, "name": cat.category.name}

            # Costruisci lista todos con created_by e modified_by
            todos_list = []
            for t in todos:
                todo_data = {
                    "id": t.id,
                    "title": t.title,
                    "completed": t.completed
                }
                if t.created_by:
                    todo_data["created_by"] = {
                        "id": t.created_by.id,
                        "username": t.created_by.username,
                        "full_name": t.created_by.profile.get_full_name() if hasattr(t.created_by, 'profile') else t.created_by.username
                    }
                else:
                    todo_data["created_by"] = None

                if t.modified_by:
                    todo_data["modified_by"] = {
                        "id": t.modified_by.id,
                        "username": t.modified_by.username,
                        "full_name": t.modified_by.profile.get_full_name() if hasattr(t.modified_by, 'profile') else t.modified_by.username
                    }
                else:
                    todo_data["modified_by"] = None

                todos_list.append(todo_data)

            data.append({
                "id": cat.id,
                "name": cat.name,
                "color": getattr(cat, "color", "blue"),
                "created_at": getattr(cat, "created_at", ""),
                "sort_order": sort_order,
                "category": category_data,
                "is_owner": False,
                "is_shared": True,
                "can_edit": shared.can_edit,
                "shared_by": {
                    "id": shared.shared_by.id,
                    "username": shared.shared_by.username,
                    "full_name": shared.shared_by.profile.get_full_name() if hasattr(shared.shared_by, 'profile') else shared.shared_by.username
                },
                "todos": todos_list
            })

        return Response(data)

    def post(self, request):
        user = request.user
        data = request.data

        if not user.is_authenticated:
            return Response({"error": "Utente non autenticato"}, status=401)

        # ✅ GESTISCI LA CATEGORIA
        category_id = data.get("category")
        list_category = None
        if category_id:
            try:
                list_category = ListCategory.objects.get(id=category_id, user=user)
            except ListCategory.DoesNotExist:
                return Response({"error": "Categoria non trovata"}, status=404)

        cat = Category.objects.create(
            user=user,
            name=data.get("name"),
            color=data.get("color", "blue"),
            category=list_category  # ✅ NUOVO
        )

        return Response({"id": cat.id, "name": cat.name})

## VIEW GET SINGLE todo
# ✅ View per dettaglio, modifica e cancellazione di una lista
class SingleListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, list_id):
        user = request.user

        # Controlla se l'utente è il proprietario
        category = Category.objects.filter(id=list_id, user=user).first()

        is_owner = True
        can_edit = True
        shared_by_info = None

        # Se non è il proprietario, controlla se è condivisa con lui
        if not category:
            shared = SharedList.objects.filter(list_id=list_id, shared_with=user).select_related('list', 'shared_by').first()
            if not shared:
                return Response({"error": "Not found"}, status=404)
            category = shared.list
            is_owner = False
            can_edit = shared.can_edit
            shared_by_info = {
                "id": shared.shared_by.id,
                "username": shared.shared_by.username,
                "full_name": shared.shared_by.profile.get_full_name() if hasattr(shared.shared_by, 'profile') else shared.shared_by.username
            }

        sort_order = getattr(category, 'sort_order', 'created') or 'created'

        if sort_order == "alphabetical":
            todos = category.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by(Lower('title'))
        elif sort_order == "completed":
            todos = category.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by('completed', '-id')
        else:
            todos = category.todo_set.select_related('created_by', 'created_by__profile', 'modified_by', 'modified_by__profile').order_by('-id')

        # Costruisci lista todos con created_by e modified_by
        todos_list = []
        for todo in todos:
            todo_data = {
                "id": todo.id,
                "title": todo.title,
                "completed": todo.completed
            }

            # Aggiungi created_by se presente
            if todo.created_by:
                todo_data["created_by"] = {
                    "id": todo.created_by.id,
                    "username": todo.created_by.username,
                    "full_name": todo.created_by.profile.get_full_name() if hasattr(todo.created_by, 'profile') else todo.created_by.username
                }
            else:
                todo_data["created_by"] = None

            # Aggiungi modified_by se presente
            if todo.modified_by:
                todo_data["modified_by"] = {
                    "id": todo.modified_by.id,
                    "username": todo.modified_by.username,
                    "full_name": todo.modified_by.profile.get_full_name() if hasattr(todo.modified_by, 'profile') else todo.modified_by.username
                }
            else:
                todo_data["modified_by"] = None

            todos_list.append(todo_data)

        # Recupera lista utenti con cui è condivisa (solo se proprietario)
        shared_with_list = []
        if is_owner:
            shares = SharedList.objects.filter(list=category).select_related('shared_with', 'shared_with__profile')
            for share in shares:
                shared_with_list.append({
                    "username": share.shared_with.username,
                    "full_name": share.shared_with.profile.get_full_name() if hasattr(share.shared_with, 'profile') else share.shared_with.username
                })

        return Response({
            "id": category.id,
            "name": category.name,
            "color": category.color,
            "created_at": category.created_at,
            "sort_order": sort_order,
            "is_owner": is_owner,
            "can_edit": can_edit,
            "shared_by": shared_by_info,
            "shared_with": shared_with_list,
            "todos": todos_list
        })

    def put(self, request, list_id):
        user = request.user
        data = request.data
        name = data.get("name")
        color = data.get("color")
        category_id = data.get("category")

        # Controlla se l'utente è il proprietario
        category = Category.objects.filter(id=list_id, user=user).first()

        # Se non è il proprietario, controlla se può modificare
        if not category:
            shared = SharedList.objects.filter(list_id=list_id, shared_with=user, can_edit=True).first()
            if not shared:
                return Response({"error": "Permesso negato"}, status=403)
            category = shared.list

        category.name = name
        category.color = color

        # Gestisci la categoria (solo se proprietario)
        if category.user == user and category_id is not None:
            if category_id == "":
                category.category = None
            else:
                try:
                    list_category = ListCategory.objects.get(id=category_id, user=user)
                    category.category = list_category
                except ListCategory.DoesNotExist:
                    return Response({"error": "Categoria non trovata"}, status=404)

        category.save()
        return Response({"message": "Lista aggiornata"})

    def delete(self, request, list_id):
        user = request.user
        # Solo il proprietario può eliminare la lista
        try:
            category = Category.objects.get(id=list_id, user=user)
            category.delete()
            return Response({"message": "Lista eliminata"})
        except Category.DoesNotExist:
            return Response({"error": "Not found o permesso negato"}, status=404)

## VIEW UPDATE CATEGORY ORDER
class UpdateListsOrderingView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        """
        Restituisce l'ordinamento corrente delle liste per l'utente.
        GET /api/lists/sort_order/
        """
        profile = get_object_or_404(Profile, user=request.user)
        return Response({"sort_order": profile.lists_sort_order})

    def patch(self, request):
        """
        Aggiorna l'ordinamento delle liste per l'utente.
        PATCH /api/lists/sort_order/  Body: {"sort_order": "..."}
        """
        new_ordering = request.data.get("sort_order")
        if new_ordering not in ["created", "alphabetical", "complete"]:
            return Response({"error": "Ordinamento non valido"}, status=400)

        profile = get_object_or_404(Profile, user=request.user)
        profile.lists_sort_order = new_ordering
        profile.save()
        return Response({"success": True, "sort_order": profile.lists_sort_order})


## VIEW GET SINGLE CATEGORY
@method_decorator(csrf_exempt, name='dispatch')
class CategoryDetailView(View):
    def get(self, request, pk):
        try:
            category = Category.objects.get(pk=pk)
            todos = Todo.objects.filter(category=category).order_by("order").values("id", "title", "completed")
            return JsonResponse({
                "id": category.id,
                "name": category.name,
                "todos": list(todos),
            })
        except Category.DoesNotExist:
            return JsonResponse({"error": "Categoria non trovata"}, status=404)
    def put(self, request, pk):
        body = json.loads(request.body)
        cat = get_object_or_404(Category, pk=pk)
        cat.name = body.get("name", cat.name)
        if hasattr(cat, "color"):
            cat.color = body.get("color", cat.color)
        cat.save()
        return JsonResponse({"id": cat.id, "name": cat.name})

    def delete(self, request, pk):
        cat = get_object_or_404(Category, pk=pk)
        cat.delete()
        return JsonResponse({"deleted": True})



### VIEW TODOS PAGE

## HELPER: Verifica permessi su una lista
def can_user_edit_list(user, list_id):
    """Verifica se l'utente può modificare una lista (proprietario o condivisa con permessi)"""
    # Controlla se è il proprietario
    if Category.objects.filter(id=list_id, user=user).exists():
        return True
    # Controlla se è condivisa con permessi di modifica
    if SharedList.objects.filter(list_id=list_id, shared_with=user, can_edit=True).exists():
        return True
    return False

def get_category_if_accessible(user, list_id):
    """Ritorna la categoria se l'utente ha accesso (proprietario o condivisa)"""
    category = Category.objects.filter(id=list_id, user=user).first()
    if category:
        return category
    # Controlla se è condivisa
    shared = SharedList.objects.filter(list_id=list_id, shared_with=user).first()
    if shared:
        return shared.list
    return None

## VIEW CREATE TODO
class TodoCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, list_id):
        user = request.user
        title = request.data.get("title")

        # Verifica se può modificare la lista
        if not can_user_edit_list(user, list_id):
            return Response({"error": "Permesso negato"}, status=403)

        category = get_category_if_accessible(user, list_id)
        if not category:
            return Response({"error": "Categoria non trovata"}, status=404)

        todo = Todo.objects.create(title=title, category=category, created_by=user)

        # Prepara info created_by
        created_by_info = {
            "id": user.id,
            "username": user.username,
            "full_name": user.profile.get_full_name() if hasattr(user, 'profile') else user.username
        }

        # Invia notifiche a tutti gli utenti con cui è condivisa la lista
        shares = SharedList.objects.filter(list=category).select_related('shared_with', 'shared_with__profile')
        for share in shares:
            # Non notificare chi ha creato il todo
            if share.shared_with != user:
                Notification.objects.create(
                    user=share.shared_with,
                    type='list_modified',
                    title='Nuovo todo aggiunto',
                    message=f'{user.profile.get_full_name() if hasattr(user, "profile") else user.username} ha aggiunto "{title}" alla lista "{category.name}"',
                    from_user=user,
                    list_name=category.name
                )

        # Se l'utente che ha creato il todo non è il proprietario, notifica il proprietario
        if category.user != user:
            Notification.objects.create(
                user=category.user,
                type='list_modified',
                title='Nuovo todo aggiunto',
                message=f'{user.profile.get_full_name() if hasattr(user, "profile") else user.username} ha aggiunto "{title}" alla lista "{category.name}"',
                from_user=user,
                list_name=category.name
            )

        return Response({
            "id": todo.id,
            "title": todo.title,
            "completed": todo.completed,
            "created_by": created_by_info
        })

## VIEW TOGGLE TODO
class TodoToggleView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, todo_id):
        user = request.user
        # Trova il todo
        todo = Todo.objects.filter(pk=todo_id).first()
        if not todo:
            return Response({"error": "Todo non trovata"}, status=404)

        # Verifica permessi sulla lista
        if not can_user_edit_list(user, todo.category.id):
            return Response({"error": "Permesso negato"}, status=403)

        todo.completed = not todo.completed
        todo.save()
        return Response({"success": True, "completed": todo.completed})

## VIEW UPDATE TODO ORDER
@method_decorator(csrf_exempt, name='dispatch')
class UpdateOrderingView(View):
    def patch(self, request, list_id):
        data = json.loads(request.body)
        new_ordering = data.get("sort_order")

        # ✅ Aggiungi 'completed' alle opzioni valide
        if new_ordering not in ["created", "alphabetical", "completed"]:
            return JsonResponse({"error": "Ordinamento non valido"}, status=400)

        category = get_object_or_404(Category, pk=list_id)
        category.sort_order = new_ordering
        category.save()
        return JsonResponse({"success": True, "sort_order": category.sort_order})

## VIEW DELETE TODO
class TodoDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, todo_id):
        user = request.user
        todo = Todo.objects.filter(pk=todo_id).select_related('category').first()
        if not todo:
            return Response({"error": "Todo non trovata"}, status=404)

        # Verifica permessi sulla lista
        if not can_user_edit_list(user, todo.category.id):
            return Response({"error": "Permesso negato"}, status=403)

        # Salva info prima di eliminare
        todo_title = todo.title
        category = todo.category

        # Elimina il todo
        todo.delete()

        # Invia notifiche a tutti gli utenti con cui è condivisa la lista
        shares = SharedList.objects.filter(list=category).select_related('shared_with', 'shared_with__profile')
        for share in shares:
            # Non notificare chi ha eliminato il todo
            if share.shared_with != user:
                Notification.objects.create(
                    user=share.shared_with,
                    type='list_modified',
                    title='Todo eliminato',
                    message=f'{user.profile.get_full_name() if hasattr(user, "profile") else user.username} ha eliminato "{todo_title}" dalla lista "{category.name}"',
                    from_user=user,
                    list_name=category.name
                )

        # Se l'utente che ha eliminato il todo non è il proprietario, notifica il proprietario
        if category.user != user:
            Notification.objects.create(
                user=category.user,
                type='list_modified',
                title='Todo eliminato',
                message=f'{user.profile.get_full_name() if hasattr(user, "profile") else user.username} ha eliminato "{todo_title}" dalla lista "{category.name}"',
                from_user=user,
                list_name=category.name
            )

        return Response({"success": True})

## VIEW RENAME LIST
class RenameListView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, list_id):
        new_name = request.data.get("name")

        category = get_object_or_404(Category, pk=list_id, user=request.user)
        category.name = new_name
        category.save()
        return Response({"success": True, "name": category.name})

## VIEW UPDATE TODO
class TodoUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, todo_id):
        user = request.user
        new_title = request.data.get("title")

        todo = Todo.objects.filter(id=todo_id).select_related('category').first()
        if not todo:
            return Response({"error": "ToDo not found"}, status=404)

        # Verifica permessi sulla lista
        if not can_user_edit_list(user, todo.category.id):
            return Response({"error": "Permesso negato"}, status=403)

        old_title = todo.title
        todo.title = new_title
        todo.modified_by = user
        todo.save()

        # Invia notifiche a tutti gli utenti con cui è condivisa la lista
        category = todo.category
        shares = SharedList.objects.filter(list=category).select_related('shared_with', 'shared_with__profile')
        for share in shares:
            # Non notificare chi ha modificato il todo
            if share.shared_with != user:
                Notification.objects.create(
                    user=share.shared_with,
                    type='list_modified',
                    title='Todo modificato',
                    message=f'{user.profile.get_full_name() if hasattr(user, "profile") else user.username} ha modificato "{old_title}" in "{new_title}" nella lista "{category.name}"',
                    from_user=user,
                    list_name=category.name
                )

        # Se l'utente che ha modificato il todo non è il proprietario, notifica il proprietario
        if category.user != user:
            Notification.objects.create(
                user=category.user,
                type='list_modified',
                title='Todo modificato',
                message=f'{user.profile.get_full_name() if hasattr(user, "profile") else user.username} ha modificato "{old_title}" in "{new_title}" nella lista "{category.name}"',
                from_user=user,
                list_name=category.name
            )

        return Response({"success": True, "title": todo.title})

## VIEW MOVE TODO TO ANOTHER LIST
class MoveTodoView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, todo_id):
        new_list_id = request.data.get('new_list_id')

        if not new_list_id:
            return Response({"error": "new_list_id richiesto"}, status=400)

        try:
            todo = Todo.objects.get(id=todo_id, category__user=request.user)
            new_category = Category.objects.get(id=new_list_id, user=request.user)

            # Sposta la todo
            todo.category = new_category
            todo.save()

            return Response({
                "success": True,
                "message": "Todo spostata",
                "new_list_id": new_list_id,
                "new_list_name": new_category.name
            })
        except Todo.DoesNotExist:
            return Response({"error": "Todo non trovata"}, status=404)
        except Category.DoesNotExist:
            return Response({"error": "Lista non trovata"}, status=404)


## VIEW UPDATE THEME
class UpdateThemeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        theme = request.data.get("theme")
        profile = getattr(request.user, "profile", None)
        if profile:
            profile.theme = theme
            profile.save()
            return Response({"message": "Theme updated"})
        return Response({"error": "Profile not found"}, status=404)

## VIEW UPDATE PROFILE
class UpdateProfileJWTView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        user = request.user
        logger.warning(f"✅ Accesso alla UpdateProfileJWTView da user: {request.user}")

        # Password update logic
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if new_password:
            if not user.check_password(old_password):
                return Response({"message": "Vecchia password errata"}, status=400)
            user.set_password(new_password)
            user.save()

        # Profile info update
        username = request.data.get("username")
        email = request.data.get("email")
        clear_picture = request.data.get("clear_picture") == "true"
        profile_picture = request.FILES.get("profile_picture")

        if username:
            user.username = username
        if email:
            user.email = email
        user.save()

        profile = getattr(user, 'profile', None)
        if profile:
            if clear_picture:
                profile.profile_picture.delete(save=False)
                profile.profile_picture = None
            if profile_picture:
                profile.profile_picture = profile_picture
            profile.save()

        return Response({"message": "Profile updated"})

## VIEW REQUEST PASSWORD RESET
@method_decorator(csrf_exempt, name='dispatch')
class SendResetPasswordEmailView(LoginRequiredMixin, View):
    def post(self, request):
        user = request.user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        frontend_url = f"https://todowebapp-frontend-reactts-stml.vercel.app/reset-password/{uid}/{token}"

        # Dentro la tua view
        subject = "Cambio password"
        from_email='"ToDoWebApp" <todoapp@webdesign-vito-luigi.it>',
        to_email = user.email

        # HTML content personalizzato
        context = {
            "username": user.username,
            "action_url": frontend_url,
            "action_text": "Cambia la password",
            "title": "Hai richiesto di cambiare la password?",
            "message": "Se non sei stato tu a farlo, ignora questa email.",
            "year": datetime.now().year
        }

        html_content = render_to_string("emails/email.html", context)

        # Usa la tua funzione custom per mandare la mail via Brevo API
        send_verification_email(
            to_email=user.email,
            subject="Verifica la tua email",
            html_content=html_content
        )

        return JsonResponse({"message": "Password reset email sent"})

@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordConfirmView(View):
    def post(self, request, uidb64, token):
        data = json.loads(request.body)
        new_password = data.get("password")

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError):
            return JsonResponse({"error": "Invalid UID"}, status=400)

        if not default_token_generator.check_token(user, token):
            return JsonResponse({"error": "Token non valido o scaduto"}, status=400)

        user.password = make_password(new_password)
        user.save()
        return JsonResponse({"message": "Password aggiornata con successo"})


### NOTIFICATIONS SYSTEM VIEW

## VIEW SAVE FCM TOKEN
class SaveFCMTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        fcm_token = request.data.get("fcm_token")

        if not fcm_token:
            return Response({"error": "Token mancante"}, status=400)

        profile = get_object_or_404(Profile, user=request.user)
        profile.fcm_token = fcm_token
        profile.save()

        return Response({"message": "Token salvato"})

## VIEW GET NOTIFICATIONS
class NotificationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
        data = []

        for notif in notifications:
            item = {
                "id": notif.id,
                "type": notif.type,
                "title": notif.title,
                "message": notif.message,
                "read": notif.read,
                "created_at": notif.created_at.isoformat(),
                "list_name": notif.list_name,
            }

            if notif.from_user:
                item["from_user"] = {
                    "name": notif.from_user.first_name or notif.from_user.username,
                    "surname": notif.from_user.last_name or "",
                    "profile_picture": notif.from_user.profile.profile_picture.url if notif.from_user.profile.profile_picture else None
                }

            data.append(item)

        return Response(data)

## VIEW MARK NOTIFICATION AS READ
class NotificationMarkReadView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, notif_id):
        try:
            notif = Notification.objects.get(id=notif_id, user=request.user)
            notif.read = True
            notif.save()
            return Response({"success": True})
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=404)

## VIEW MARK ALL AS READ
class NotificationMarkAllReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Notification.objects.filter(user=request.user, read=False).update(read=True)
        return Response({"success": True})

## VIEW DELETE NOTIFICATION
class NotificationDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, notif_id):
        try:
            notif = Notification.objects.get(id=notif_id, user=request.user)
            notif.delete()
            return Response({"success": True})
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=404)

## VIEW UPDATE NOTIFICATION PREFERENCES
class UpdateNotificationPreferencesView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        push_enabled = request.data.get("push_notifications_enabled")

        if push_enabled is None:
            return Response({"error": "Missing field"}, status=400)

        profile = get_object_or_404(Profile, user=request.user)
        profile.push_notifications_enabled = push_enabled
        profile.save()

        return Response({
            "message": "Preferences updated",
            "push_notifications_enabled": profile.push_notifications_enabled
        })

## VIEW CREATE UPDATE NOTIFICATION
class CreateUpdateNotificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        version = request.data.get('version')
        update_type = request.data.get('type')
        message = request.data.get('message')  # Questo arriva dal version.json

        user = request.user

        # Controlla se esiste già
        existing = Notification.objects.filter(
            user=user,
            type='update_normal' if update_type == 'normal' else 'update_important',
            title__contains=version
        ).first()

        if existing:
            return Response({"message": "Notifica già esistente"})

        # Crea notifica usando il messaggio dal frontend
        if update_type == 'important':
            title = f"🚨 Aggiornamento Importante v{version}"
            notif_type = 'update_important'
        else:
            title = f"📦 Nuovo Aggiornamento v{version}"
            notif_type = 'update_normal'

        Notification.objects.create(
            user=user,
            type=notif_type,
            title=title,
            message=message  # ← USA IL MESSAGGIO DAL version.json
        )

        return Response({"message": "Notifica creata"})


### FRIENDSHIP SYSTEM VIEWS

## VIEW GET ALL USERS (con stato relazione)
class UsersListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        current_user = request.user
        search_query = request.GET.get('search', '').strip()

        users = User.objects.exclude(id=current_user.id)

        # Applica filtro di ricerca se presente
        if search_query:
            users = users.filter(username__icontains=search_query)

        data = []
        for user in users:
            # Controlla se sono amici
            is_friend = Friendship.are_friends(current_user, user)

            # Controlla richieste pending inviate
            pending_sent = FriendRequest.objects.filter(
                from_user=current_user,
                to_user=user,
                status='pending'
            ).exists()

            # Controlla richieste pending ricevute
            pending_received = FriendRequest.objects.filter(
                from_user=user,
                to_user=current_user,
                status='pending'
            ).exists()

            # Controlla richiesta rifiutata
            rejected = FriendRequest.objects.filter(
                from_user=current_user,
                to_user=user,
                status='rejected'
            ).exists()

            # Determina lo stato
            if is_friend:
                status = "friends"
            elif pending_sent:
                status = "pending_sent"
            elif pending_received:
                status = "pending_received"
            elif rejected:
                status = "rejected"
            else:
                status = "none"

            profile = getattr(user, 'profile', None)
            profile_pic = None
            if profile and profile.profile_picture:
                profile_pic = profile.profile_picture.url

            data.append({
                "id": user.id,
                "username": user.username,
                "full_name": profile.get_full_name() if profile else user.username,
                "profile_picture": profile_pic,
                "friendship_status": status  # ✅ IMPORTANTE
            })

        return Response(data)

## VIEW SEND FRIEND REQUEST
class SendFriendRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        from_user = request.user

        try:
            to_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "Utente non trovato"}, status=404)

        if from_user == to_user:
            return Response({"error": "Non puoi inviare richiesta a te stesso"}, status=400)

        # Controlla se sono già amici
        if Friendship.are_friends(from_user, to_user):
            return Response({"error": "Siete già amici"}, status=400)

        # ✅ Controlla se esiste già una richiesta (anche rifiutata)
        existing = FriendRequest.objects.filter(
            Q(from_user=from_user, to_user=to_user) |
            Q(from_user=to_user, to_user=from_user)
        ).first()

        if existing:
            # Se la richiesta è pending
            if existing.status == 'pending':
                return Response({"error": "Richiesta già inviata"}, status=400)

            # ✅ Se la richiesta è stata rifiutata, aggiornala a pending
            elif existing.status == 'rejected':
                existing.status = 'pending'
                existing.from_user = from_user
                existing.to_user = to_user
                existing.save()
                friend_request = existing

            # Se è accepted (non dovrebbe succedere, sono già amici)
            else:
                return Response({"error": "Già amici"}, status=400)
        else:
            # ✅ Crea nuova richiesta solo se non esiste
            friend_request = FriendRequest.objects.create(
                from_user=from_user,
                to_user=to_user
            )

        # Crea notifica
        notification = Notification.objects.create(
            user=to_user,
            type='friend_request',
            title='Nuova richiesta di amicizia',
            message=f'{from_user.profile.get_full_name()} ti ha inviato una richiesta di amicizia',
            from_user=from_user
        )

        # Invia notifica push
        to_profile = getattr(to_user, 'profile', None)
        if to_profile and to_profile.push_notifications_enabled and to_profile.fcm_token:
            send_push_notification(
                fcm_token=to_profile.fcm_token,
                title=notification.title,
                body=notification.message
            )

        return Response({"message": "Richiesta inviata", "id": friend_request.id})

## VIEW GET FRIEND REQUESTS (ricevute)
class FriendRequestsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        requests = FriendRequest.objects.filter(
            to_user=request.user,
            status='pending'
        )
        serializer = FriendRequestSerializer(requests, many=True)
        return Response(serializer.data)


## VIEW ACCEPT FRIEND REQUEST
class AcceptFriendRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, request_id):
        try:
            friend_request = FriendRequest.objects.get(
                id=request_id,
                to_user=request.user,
                status='pending'
            )
        except FriendRequest.DoesNotExist:
            return Response({"error": "Richiesta non trovata"}, status=404)

        # Aggiorna lo status
        friend_request.status = 'accepted'
        friend_request.save()

        # Crea l'amicizia
        Friendship.objects.create(
            user1=friend_request.from_user,
            user2=friend_request.to_user
        )

        # Notifica chi ha inviato la richiesta
        Notification.objects.create(
            user=friend_request.from_user,
            type='general',
            title='Richiesta accettata',
            message=f'{request.user.profile.get_full_name()} ha accettato la tua richiesta di amicizia',
            from_user=request.user
        )

        return Response({"message": "Richiesta accettata"})


## VIEW REJECT FRIEND REQUEST
class RejectFriendRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, request_id):
        try:
            friend_request = FriendRequest.objects.get(
                id=request_id,
                to_user=request.user,
                status='pending'
            )
        except FriendRequest.DoesNotExist:
            return Response({"error": "Richiesta non trovata"}, status=404)

        friend_request.status = 'rejected'
        friend_request.save()

        return Response({"message": "Richiesta rifiutata"})


## VIEW GET FRIENDS LIST
class FriendsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        friendships = Friendship.objects.filter(
            Q(user1=request.user) | Q(user2=request.user)
        )
        serializer = FriendshipSerializer(
            friendships,
            many=True,
            context={'request_user': request.user}
        )
        return Response(serializer.data)


## VIEW REMOVE FRIEND
class RemoveFriendView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        try:
            friend = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "Utente non trovato"}, status=404)

        # Trova e elimina l'amicizia
        friendship = Friendship.objects.filter(
            Q(user1=request.user, user2=friend) |
            Q(user1=friend, user2=request.user)
        ).first()

        if not friendship:
            return Response({"error": "Non siete amici"}, status=400)

        friendship.delete()
        return Response({"message": "Amico rimosso"})


### SHARING SYSTEM VIEWS

## VIEW CONDIVIDI LISTA
class ShareListView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, list_id):
        """Condividi una lista con un utente"""
        user_id = request.data.get('user_id')
        can_edit = request.data.get('can_edit', False)

        if not user_id:
            return Response({"error": "user_id richiesto"}, status=400)

        try:
            # Verifica che la lista appartenga all'utente
            list_obj = Category.objects.get(id=list_id, user=request.user)
            target_user = User.objects.get(id=user_id)
        except Category.DoesNotExist:
            return Response({"error": "Lista non trovata"}, status=404)
        except User.DoesNotExist:
            return Response({"error": "Utente non trovato"}, status=404)

        # Non puoi condividere con te stesso
        if target_user == request.user:
            return Response({"error": "Non puoi condividere con te stesso"}, status=400)

        # Controlla se è già condivisa
        existing = SharedList.objects.filter(list=list_obj, shared_with=target_user).first()
        if existing:
            # Aggiorna i permessi se già condivisa
            existing.can_edit = can_edit
            existing.save()
            return Response({"message": "Permessi aggiornati", "can_edit": can_edit})

        # Crea la condivisione
        SharedList.objects.create(
            list=list_obj,
            shared_by=request.user,
            shared_with=target_user,
            can_edit=can_edit
        )

        # Crea notifica
        Notification.objects.create(
            user=target_user,
            type='list_modified',
            title='Lista condivisa con te',
            message=f'{request.user.profile.get_full_name()} ha condiviso la lista "{list_obj.name}" con te',
            from_user=request.user,
            list_name=list_obj.name
        )

        return Response({"message": "Lista condivisa con successo"})


## VIEW RIMUOVI CONDIVISIONE LISTA
class UnshareListView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, list_id, user_id):
        """Rimuovi la condivisione di una lista con un utente"""
        try:
            list_obj = Category.objects.get(id=list_id, user=request.user)
            shared = SharedList.objects.get(list=list_obj, shared_with_id=user_id)
            shared.delete()
            return Response({"message": "Condivisione rimossa"})
        except Category.DoesNotExist:
            return Response({"error": "Lista non trovata"}, status=404)
        except SharedList.DoesNotExist:
            return Response({"error": "Condivisione non trovata"}, status=404)


## VIEW VEDI CON CHI È CONDIVISA UNA LISTA
class ListSharesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, list_id):
        """Vedi con chi è condivisa una lista"""
        try:
            list_obj = Category.objects.get(id=list_id, user=request.user)
            shares = SharedList.objects.filter(list=list_obj).select_related('shared_with')

            data = []
            for share in shares:
                user = share.shared_with
                profile = getattr(user, 'profile', None)
                data.append({
                    "user_id": user.id,
                    "username": user.username,
                    "full_name": profile.get_full_name() if profile else user.username,
                    "profile_picture": profile.profile_picture.url if profile and profile.profile_picture else None,
                    "can_edit": share.can_edit,
                    "shared_at": share.created_at.isoformat()
                })

            return Response(data)
        except Category.DoesNotExist:
            return Response({"error": "Lista non trovata"}, status=404)


## VIEW CONDIVIDI CATEGORIA
class ShareCategoryView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, category_id):
        """Condividi una categoria con un utente"""
        user_id = request.data.get('user_id')
        can_edit = request.data.get('can_edit', False)

        if not user_id:
            return Response({"error": "user_id richiesto"}, status=400)

        try:
            # Verifica che la categoria appartenga all'utente
            category = ListCategory.objects.get(id=category_id, user=request.user)
            target_user = User.objects.get(id=user_id)
        except ListCategory.DoesNotExist:
            return Response({"error": "Categoria non trovata"}, status=404)
        except User.DoesNotExist:
            return Response({"error": "Utente non trovato"}, status=404)

        # Non puoi condividere con te stesso
        if target_user == request.user:
            return Response({"error": "Non puoi condividere con te stesso"}, status=400)

        # Controlla se è già condivisa
        existing = SharedCategory.objects.filter(category=category, shared_with=target_user).first()
        if existing:
            # Aggiorna i permessi se già condivisa
            existing.can_edit = can_edit
            existing.save()
            return Response({"message": "Permessi aggiornati", "can_edit": can_edit})

        # Crea la condivisione
        SharedCategory.objects.create(
            category=category,
            shared_by=request.user,
            shared_with=target_user,
            can_edit=can_edit
        )

        # Crea notifica
        Notification.objects.create(
            user=target_user,
            type='general',
            title='Categoria condivisa con te',
            message=f'{request.user.profile.get_full_name()} ha condiviso la categoria "{category.name}" con te',
            from_user=request.user
        )

        return Response({"message": "Categoria condivisa con successo"})


## VIEW RIMUOVI CONDIVISIONE CATEGORIA
class UnshareCategoryView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, category_id, user_id):
        """Rimuovi la condivisione di una categoria con un utente"""
        try:
            category = ListCategory.objects.get(id=category_id, user=request.user)
            shared = SharedCategory.objects.get(category=category, shared_with_id=user_id)
            shared.delete()
            return Response({"message": "Condivisione rimossa"})
        except ListCategory.DoesNotExist:
            return Response({"error": "Categoria non trovata"}, status=404)
        except SharedCategory.DoesNotExist:
            return Response({"error": "Condivisione non trovata"}, status=404)


## VIEW VEDI CON CHI È CONDIVISA UNA CATEGORIA
class CategorySharesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, category_id):
        """Vedi con chi è condivisa una categoria"""
        try:
            category = ListCategory.objects.get(id=category_id, user=request.user)
            shares = SharedCategory.objects.filter(category=category).select_related('shared_with')

            data = []
            for share in shares:
                user = share.shared_with
                profile = getattr(user, 'profile', None)
                data.append({
                    "user_id": user.id,
                    "username": user.username,
                    "full_name": profile.get_full_name() if profile else user.username,
                    "profile_picture": profile.profile_picture.url if profile and profile.profile_picture else None,
                    "can_edit": share.can_edit,
                    "shared_at": share.created_at.isoformat()
                })

            return Response(data)
        except ListCategory.DoesNotExist:
            return Response({"error": "Categoria non trovata"}, status=404)


## FUNCTION TO CREATE NOTIFICATION (utility)
def create_notification(user, notif_type, title, message, from_user=None, list_name=None):
    """
    Funzione helper per creare notifiche
    """
    Notification.objects.create(
        user=user,
        type=notif_type,
        title=title,
        message=message,
        from_user=from_user,
        list_name=list_name
    )