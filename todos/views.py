from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
import json
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .models import Todo, Category
from django.db.models.functions import Lower

## Function for unauthorized
def unauthorized(request):
    return JsonResponse({'message': 'Unauthorized'}, status=401)

## VIEW MOBILE LOGIN
@method_decorator(csrf_exempt, name='dispatch')
class MobileLoginView(View):
    def post(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            return HttpResponse("Dati non validi", status=400)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return JsonResponse({
                "message": "login ok",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            })
        return HttpResponse("Credenziali errate o utente non trovato", status=401)

## VIEW CURRENT USER JWT
class JWTCurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "username": user.username,
            "email": user.email,
            "id": user.id,
        })

## VIEW CURRENT USER
class CurrentUserView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        profile = getattr(user, 'profile', None)
        return JsonResponse({
            'username': user.username,
            'email': user.email,
            'id': user.id,
            'is_active': user.is_active,
            'theme': profile.theme if profile else "light",
            'profile_picture': profile.profile_picture.url if profile and profile.profile_picture else None,
            'email_verified': profile.email_verified if profile else False
        })

## VIEW LOGIN
class LoginView(APIView):
    def post(self, request):
        data = request.data
        username = data.get("username")
        password = data.get("password")

        user = authenticate(username=username, password=password)
        if user is None:
            return Response({"message": "Invalid credentials"}, status=401)

        if not user.is_active:
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

            email = EmailMultiAlternatives(
                subject="Verifica la tua email",
                body="Clicca sul link per verificare la tua email.",
                from_email="todoprovider@webdesign-vito-luigi.it",
                to=[user.email],
            )
            email.attach_alternative(html_content, "text/html")
            email.send()

            return Response({"message": "email not verified"}, status=403)

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
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

        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            is_active=False
        )
        return JsonResponse({"message": "register success"})

## VIEW DELETE ACCOUNT
@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_required, name="dispatch")
class DeleteAccountView(View):
    def delete(self, request):
        user = request.user
        user.delete()
        return JsonResponse({"message": "Account disattivato"})

## VIEW SEND EMAIL VERIFICATION
@method_decorator(csrf_exempt, name='dispatch')
class SendEmailVerificationView(View):
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
            "year": datetime.datetime.now().year,
        }

        html_content = render_to_string("emails/email_template.html", context)

        send_mail(
            subject="Verifica la tua email",
            message="Clicca sul link per verificare la tua email.",
            from_email='"ToDoWebApp Bale" <todoprovider@webdesign-vito-luigi.it>',
            recipient_list=[user.email],
            html_message=html_content,
        )
        return JsonResponse({"message": "Verification email sent"})

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
@method_decorator(csrf_exempt, name='dispatch')
class CategoryListView(View):
    def get(self, request):
        categories = Category.objects.filter(user=request.user)
        data = []

        for cat in categories:
            todos = Todo.objects.filter(category=cat)
            data.append({
                "id": cat.id,
                "name": cat.name,
                "color": getattr(cat, "color", "blue"),
                "created_at": getattr(cat, "created_at", ""),
                "sort_order": cat.sort_order,
                "todos": [
                    {
                        "id": t.id,
                        "title": t.title,
                        "completed": t.completed
                    } for t in todos
                ]
            })
        return JsonResponse(data, safe=False)

    def post(self, request):
        body = json.loads(request.body)

        # Recupera l'utente loggato
        user = request.user

        # Se usi autenticazione con sessione/cookie, questo sarà già valido
        if not user.is_authenticated:
            return JsonResponse({"error": "Utente non autenticato"}, status=401)

        # Crea la categoria con user e nome
        cat = Category.objects.create(
            user=user,
            name=body.get("name"),
            color=body.get("color", "blue")
        )

        return JsonResponse({"id": cat.id, "name": cat.name})


## VIEW GET SINGLE todo
@method_decorator(csrf_exempt, name='dispatch')
class SingleListView(View):
    def get(self, request, list_id):
        cat = get_object_or_404(Category, pk=list_id)

        if cat.sort_order == "alphabetical":
            todos = Todo.objects.filter(category=cat).order_by(Lower("title"))
        else:
            todos = Todo.objects.filter(category=cat).order_by("order")

        return JsonResponse({
            "id": cat.id,
            "name": cat.name,
            "color": cat.color,
            "sort_order": cat.sort_order,
            "todos": [
                {
                    "id": t.id,
                    "title": t.title,
                    "completed": t.completed,
                } for t in todos
            ]
        })


## VIEW UPDATE CATEGORY ORDER
@method_decorator(csrf_exempt, name='dispatch')
class UpdateOrderingView(View):
    def patch(self, request, list_id):
        data = json.loads(request.body)
        new_ordering = data.get("sort_order")

        if new_ordering not in ["created", "alphabetical"]:
            return JsonResponse({"error": "Ordinamento non valido"}, status=400)

        category = get_object_or_404(Category, pk=list_id)
        category.sort_order = new_ordering
        category.save()
        return JsonResponse({"success": True, "sort_order": category.sort_order})


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

## VIEW CREATE TODO
@method_decorator(csrf_exempt, name='dispatch')
class TodoCreateView(View):
    def post(self, request, list_id):
        body = json.loads(request.body)
        title = body.get("title")
        category = get_object_or_404(Category, pk=list_id)
        todo = Todo.objects.create(title=title, category=category)
        return JsonResponse({"id": todo.id, "title": todo.title, "completed": todo.completed})

## VIEW TOGGLE TODO
@method_decorator(csrf_exempt, name='dispatch')
class TodoToggleView(View):
    def patch(self, request, todo_id):
        todo = get_object_or_404(Todo, pk=todo_id)
        todo.completed = not todo.completed
        todo.save()
        return JsonResponse({"success": True, "completed": todo.completed})

## VIEW REORDER
@method_decorator(csrf_exempt, name='dispatch')
class ReorderTodoView(View):
    def post(self, request, list_id):
        import json
        data = json.loads(request.body)
        order = data.get("order", [])

        # Logica per salvare l'ordine (esempio base)
        for index, todo_id in enumerate(order):
            Todo.objects.filter(id=todo_id, category_id=list_id).update(order=index)

        return JsonResponse({"message": "Ordine aggiornato"})

## VIEW DELETE TODO
@method_decorator(csrf_exempt, name='dispatch')
class TodoDeleteView(View):
    def delete(self, request, todo_id):
        todo = get_object_or_404(Todo, pk=todo_id)
        todo.delete()
        return JsonResponse({"success": True})

## VIEW RENAME LIST
@method_decorator(csrf_exempt, name='dispatch')
class RenameListView(View):
    def patch(self, request, list_id):
        body = json.loads(request.body)
        new_name = body.get("name")
        category = get_object_or_404(Category, pk=list_id)
        category.name = new_name
        category.save()
        return JsonResponse({"success": True, "name": category.name})

## VIEW UPDATE TODO
@method_decorator(csrf_exempt, name='dispatch')
class TodoUpdateView(View):
    def patch(self, request, todo_id):
        try:
            data = json.loads(request.body)
            new_title = data.get("title")
            todo = Todo.objects.get(id=todo_id)
            todo.title = new_title
            todo.save()
            return JsonResponse({"success": True, "title": todo.title})
        except Todo.DoesNotExist:
            return JsonResponse({"error": "ToDo not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)




## VIEW UPDATE THEME
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(login_required, name='dispatch')
class UpdateThemeView(View):
    def post(self, request):
        data = json.loads(request.body)
        theme = data.get("theme")
        profile = getattr(request.user, "profile", None)
        if profile:
            profile.theme = theme
            profile.save()
            return JsonResponse({"message": "Theme updated"})
        return JsonResponse({"error": "Profile not found"}, status=404)

## VIEW UPDATE PROFILE
@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(login_required, name='dispatch')
class UpdateProfileView(View):
    def post(self, request):
        user = request.user

        # Se multipart, usa request.POST e request.FILES
        if request.content_type.startswith('multipart'):
            username = request.POST.get('username')
            email = request.POST.get('email')
            clear_picture = request.POST.get("clear_picture") == "true"
            profile_picture = request.FILES.get('profile_picture')
        else:
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            clear_picture = data.get("clear_picture", False)
            profile_picture = None

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

        return JsonResponse({"message": "Profile updated"})

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
        from_email='"ToDoWebApp Bale" <todoprovider@webdesign-vito-luigi.it>',
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

        email = EmailMultiAlternatives(
            subject,
            "",
            "todoprovider@webdesign-vito-luigi.it",
            [to_email]
        )
        email.extra_headers = {"From": "ToDoWebApp Bale <todoprovider@webdesign-vito-luigi.it>"}
        email.attach_alternative(html_content, "text/html")
        email.send()

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