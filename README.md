# Wstęp
Celem niniejszego sprawozdania jest przedstawienie implementacji autoryzacji w aplikacjach webowych przy użyciu frameworka Django Rest Framework. W projekcie skoncentrowaliśmy się na dwóch metodach kontroli dostępu: uwierzytelnianiu sesyjnym oraz uwierzytelnianiu za pomocą tokenu. Dodatkowo, zaimplementowaliśmy specjalny endpoint dostępny tylko dla administratora.


### Wybor srodowiska programistycznego
Wykorzystanie Django Rest Framework:
W naszym projekcie zdecydowaliśmy się wykorzystać framework Django Rest Framework do stworzenia API. Django Rest Framework jest popularnym narzędziem, które zapewnia wydajne i skalowalne rozwiązania do budowy aplikacji webowych z użyciem Django.
W przypadku naszego projektu, zdecydowaliśmy się skorzystać z frameworka Django ze względu na jego zaawansowane funkcje uwierzytelniania użytkowników.

Django to popularny, oparty na języku Python, framework webowy, który oferuje wiele gotowych rozwiązań i narzędzi, usprawniających proces tworzenia aplikacji webowych. Jednym z nich jest wbudowany system uwierzytelniania użytkowników, który posiada szeroki zakres funkcji, takich jak obsługa kont użytkowników, grup, uprawnień oraz sesji użytkowników opartych na ciasteczkach.

## API teacherapi
Implementacja API dla nauczycieli:
Zaczęliśmy od implementacji API dla nauczycieli. Skorzystaliśmy z modelu nauczyciela oraz zserializowaliśmy dane za pomocą TeacherSerializer. Następnie, przy użyciu widoku ModelViewSet z Django Rest Framework, udostępniliśmy podstawowe operacje nauczycieli, takie jak tworzenie, odczyt, aktualizacja i usuwanie. Aby zapewnić kontrole dostępu, skonfigurowaliśmy uwierzytelnianie sesyjne (SessionAuthentication) oraz wymogliśmy autoryzację dla użytkowników uwierzytelnionych (IsAuthenticated).

Implementacja widoku:
```python
class TeacherModelViewSet(viewsets.ModelViewSet):
    queryset = Teacher.objects.all()
    serializer_class = TeacherSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

```


Oto lista endpointów oraz odpowiadających im metod HTTP dla API dla nauczycieli:

```
Endpoint: /teacherapi/

Metoda GET: Pobierz listę wszystkich nauczycieli.
Metoda POST: Dodaj nowego nauczyciela.
Endpoint: /teacherapi/{id}/

Metoda GET: Pobierz szczegółowe informacje o nauczycielu o określonym identyfikatorze ({id}).
Metoda PUT: Zaktualizuj informacje nauczyciela o określonym identyfikatorze ({id}).
Metoda DELETE: Usuń nauczyciela o określonym identyfikatorze ({id}).
```

## API studentapi
- Implementacja API dla uczniów:
Kolejnym krokiem było stworzenie API dla uczniów. Podobnie jak w przypadku nauczycieli, utworzyliśmy model Student oraz zserializowaliśmy go przy użyciu StudentSerializer. Wykorzystując widok ModelViewSet, udostępniliśmy podstawowe operacje na danych uczniów. W tym przypadku, zdecydowaliśmy się na uwierzytelnianie za pomocą tokenu (TokenAuthentication). To oznacza, że klienci muszą dostarczyć prawidłowy token w nagłówku żądania, aby uzyskać dostęp do API dla uczniów. Dodatkowo, wymagaliśmy autoryzacji dla wszystkich użytkowników uwierzytelnionych (IsAuthenticated).

Implementacja widoku:
```python
class StudentModelViewSet(viewsets.ModelViewSet):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

```

Oto lista endpointów oraz odpowiadających im metod HTTP dla API dla uczniów (studentapi):
```
Endpoint: /studentapi/

Metoda GET: Pobierz listę wszystkich uczniów.
Metoda POST: Dodaj nowego ucznia.
Endpoint: /studentapi/{id}/

Metoda GET: Pobierz szczegółowe informacje o uczniu o określonym identyfikatorze ({id}).
Metoda PUT: Zaktualizuj informacje ucznia o określonym identyfikatorze ({id}).
Metoda DELETE: Usuń ucznia o określonym identyfikatorze ({id}).
```
## API testapi
- Endpoint tylko dla administratora:
W celu zabezpieczenia pewnych zasobów, zaimplementowaliśmy dodatkowy endpoint, który jest dostępny tylko dla administratora. Wykorzystaliśmy klasę widoku APIView i skonfigurowaliśmy uwierzytelnianie za pomocą uwierzytelniania sesyjnego. Jednak tym razem, zastosowaliśmy specjalną klasę uprawnień IsAdminUser, która wymaga, aby użytkownik był zarówno uwierzytelniony, jak i posiadał uprawnienia administratora, aby uzyskać dostęp.

```python
class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)

```

### Uwierzytelnianie sesyjne
Pierwsza metoda autentykacji nazywa się sesyjnym uwierzytelnianiem (session-based authentication). W przypadku frameworka Django, funkcja login() jest wbudowaną funkcją, która implementuje sesyjne uwierzytelnianie. Po poprawnym uwierzytelnieniu użytkownika, login() zapisuje identyfikator użytkownika w sesji przy użyciu mechanizmu sesji dostępnego w Django.

Sesyjne uwierzytelnianie opiera się na wykorzystaniu sesji, które są przechowywane po stronie serwera. Identifikator sesji jest zazwyczaj przechowywany w pliku cookie lub przekazywany w nagłówku żądania HTTP. W przypadku Django, po zalogowaniu użytkownika przy użyciu login(), identyfikator sesji jest przypisany do bieżącej sesji użytkownika, co umożliwia późniejsze uwierzytelnianie go przy kolejnych żądaniach.

Sesyjne uwierzytelnianie jest jednym z popularnych sposobów zarządzania stanem uwierzytelnienia użytkownika w aplikacjach webowych. Oferuje ono wygodne rozwiązanie, ponieważ nie wymaga przechowywania hasła użytkownika w żadnej formie na stronie klienta ani przesyłania go przy każdym żądaniu. Zamiast tego, informacje uwierzytelniające są przechowywane po stronie serwera, co minimalizuje ryzyko naruszenia poufności danych.

### Mechanizm sesji w Django
W Django, mechanizm sesji jest zaimplementowany przy użyciu wbudowanej funkcjonalności dostępnej w ramach frameworka. Django wykorzystuje mechanizm sesji do przechowywania danych użytkownika między żądaniami HTTP. Oto podstawowe informacje na temat implementacji mechanizmu sesji w Django:

- Konfiguracja sesji:
Aby skonfigurować mechanizm sesji w Django, musisz ustawić odpowiednie wartości w pliku konfiguracyjnym settings.py. Kluczowe ustawienia związane z sesjami to:

- - SESSION_ENGINE: Określa silnik sesji, który ma być używany. Domyślnie Django korzysta z silnika sesji opartego na plikach.
- - SESSION_COOKIE_SECURE: Określa, czy pliki cookie sesji powinny być przesyłane tylko przez połączenia HTTPS.
- - SESSION_COOKIE_HTTPONLY: Określa, czy pliki cookie sesji powinny być dostępne tylko przez protokół HTTP i nie są dostępne dla skryptów po stronie klienta.
- Identyfikator sesji:
Po poprawnym uwierzytelnieniu użytkownika, Django generuje unikalny identyfikator sesji. Domyślnie identyfikator sesji jest przechowywany w pliku cookie o nazwie "sessionid". Ten plik cookie jest automatycznie dołączany do nagłówka żądań HTTP wysyłanych do serwera. Identifikator sesji jest używany do odnalezienia sesji użytkownika na serwerze.

- Przechowywanie danych sesji:
Dane sesji są przechowywane po stronie serwera. Domyślnie Django wykorzystuje silnik sesji oparty na plikach, który przechowuje dane sesji w plikach na serwerze. Istnieje również opcja korzystania z innych silników sesji, takich jak bazy danych, pamięć podręczna itp.

- Odczyt i zapis danych sesji:
W widokach Django, dane sesji są dostępne za pomocą obiektu request.session. Możesz odczytywać i zapisywać dane sesji, podobnie jak w słowniku. Na przykład, request.session['user_id'] = user.id zapisuje identyfikator użytkownika w sesji, a user_id = request.session.get('user_id') odczytuje go.

- Wygaśnięcie sesji:
Sesje w Django mogą mieć czas wygaśnięcia, po którym zostaną automatycznie usunięte. Czas wygaśnięcia sesji można skonfigurować przy użyciu ustawienia SESSION_COOKIE_AGE w pliku settings.py.

- Bezpieczeństwo sesji:
Django zapewnia mechanizmy bezpieczeństwa sesji, takie jak automatyczne odświeżanie identyfikatora sesji po zalogowaniu i wylogowaniu, sprawdzanie spójności danych sesji oraz automatyczne usuwanie sesji po zakończeniu sesji użytkownika.

Dzięki mechanizmowi sesji, Django umożliwia przechowywanie danych użytkownika między żądaniami i zapewnia bezpieczne zarządzanie stanem uwierzytelnienia w aplikacjach webowych.


### Uwierzytelnianie za pomocą tokenu

Uwierzytelnianie za pomocą tokenu jest popularnym podejściem w aplikacjach webowych. W naszym projekcie wykorzystujemy tokeny uwierzytelniające do autoryzacji użytkowników. Oto opis jak działa uwierzytelnianie za pomocą tokenu w naszym projekcie:


- Klasa CustomAuthToken:
Jest to klasa dziedzicząca po ObtainAuthToken z biblioteki Django Rest Framework. Przyjmuje dane uwierzytelniania (nazwa użytkownika i hasło) i zwraca token uwierzytelniający oraz inne informacje o użytkowniku (np. ID i email). Token jest generowany lub pobierany dla użytkownika za pomocą modelu Token z biblioteki Django Rest Framework.
```python
class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })

```

- Tworzenie tokenów dla studentów:
Wykorzystujemy sygnał post_save z biblioteki Django, aby automatycznie tworzyć tokeny dla nowo utworzonych użytkowników (w tym przypadku studentów). Po utworzeniu nowego użytkownika, w naszym przypadku studenta, token jest tworzony przy użyciu funkcji Token.objects.create(user=instance).

Implementacja tworzenia tokenów:
```python
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
```

- Klasa TokenAuthentication:
Jest to klasa implementująca uwierzytelnianie na podstawie tokenu. Przy każdym żądaniu, uwierzytelnianie następuje poprzez sprawdzenie nagłówka "Authorization". Nagłówek musi zawierać token, poprzedzony słowem kluczowym "Token". Jeśli uwierzytelnienie powiedzie się, metoda authenticate zwraca użytkownika oraz obiekt tokenu.

```python
class TokenAuthentication(BaseAuthentication):
    """
    Simple token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    keyword = 'Token'
    model = None

    def get_model(self):
        if self.model is not None:
            return self.model
        from rest_framework.authtoken.models import Token
        return Token

    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)

    def authenticate_header(self, request):
        return self.keyword

```
- W przypadku braku nagłówka autoryzacyjnego lub błędnego formatu, zostaje zgłoszony wyjątek AuthenticationFailed.
Jeśli token jest nieprawidłowy, również zostaje zgłoszony wyjątek AuthenticationFailed.
Jeśli użytkownik powiązany z tokenem jest nieaktywny, również zostaje zgłoszony wyjątek AuthenticationFailed.
Metoda authenticate_header zwraca słowo kluczowe używane w nagłówku autoryzacyjnym, w naszym przypadku "Token", aby klient wiedział, jaką formę uwierzytelnienia stosować.

Dzięki uwierzytelnianiu za pomocą tokenu, klienci mogą przesyłać token w nagłówku "Authorization" w celu autoryzacji przy żądaniach API. To zapewnia bezpieczny sposób uwierzytelniania i autoryzacji użytkowników w naszej aplikacji webowej.

## API testapi

```
Endpoint: /testapi/only-admin/

Metoda GET: Dostęp ma tylko uzytkownik z uprawnieniami administratora.
```
```
Endpoint: /testapi/throttlig/

Metoda GET: Uzytkownik niezalogowany moze tylko 3 razy skorzystac z endpointu na dzien.
```

###

### Uprawnienia dla admina
W przypadku endpointu "only-admin", który wymaga dostępu tylko dla administratorów, została zastosowana klasa IsAdminUser dziedzicząca po klasie bazowej BasePermission z Django Rest Framework.

Klasa IsAdminUser implementuje metodę has_permission(self, request, view), która jest wywoływana, aby sprawdzić, czy użytkownik ma uprawnienia do wykonania żądania na danym widoku. Jeśli metoda has_permission() zwraca True, użytkownik ma uprawnienia, w przeciwnym razie żądanie zostanie zablokowane.

W przypadku klasy IsAdminUser, metoda has_permission() sprawdza, czy żądanie zostało wykonane przez zalogowanego użytkownika (poprzez request.user) i czy ten użytkownik ma ustawioną flagę is_staff na True. Domyślnie w Django, pole is_staff oznacza, że użytkownik jest administratorem.

Jeśli warunek request.user and request.user.is_staff zostanie spełniony i zwrócony zostanie wynik True, to oznacza, że użytkownik jest administratorem i ma uprawnienia do dostępu do endpointu "only-admin". W przeciwnym przypadku, gdy użytkownik nie jest administratorem lub nie jest zalogowany, metoda has_permission() zwróci False, uniemożliwiając dostęp do widoku dla tych użytkowników.

Dzięki temu mechanizmowi uwierzytelnienia i uprawnień, tylko administratorzy będą mogli uzyskać dostęp do endpointu "only-admin" w aplikacji.

### Throtling
Throttling w Django to mechanizm, który ogranicza częstotliwość żądań do aplikacji w celu kontrolowania przeciążenia serwera i zapobiegania nadmiernemu użyciu zasobów. Throttling jest szczególnie przydatny w przypadku publicznych interfejsów API, gdzie chcemy zapewnić równowagę między dostępem do danych a ochroną serwera przed nadmiernym obciążeniem.

Django Rest Framework (DRF) oferuje wbudowany system throttlingu, który można skonfigurować i dostosować do potrzeb aplikacji. Działanie throttlingu w Django można opisać w kilku krokach:

Wybór klasy throttlingu: W DRF można skonfigurować różne klasy throttlingu, które implementują konkretne strategie ograniczania dostępu. Dostępne są takie klasy jak AnonRateThrottle, UserRateThrottle, ScopedRateThrottle, czy CustomThrottleClass. Każda klasa throttlingu ma własne zasady, na przykład ograniczanie na podstawie adresu IP, użytkownika lub zdefiniowanej grupy.

Konfiguracja klasy throttlingu: Klasę throttlingu można skonfigurować w ustawieniach aplikacji Django (settings.py). Możemy określić, które klasy throttlingu mają być używane i jakie limity mają być nałożone na żądania.

Implementacja w widokach: W widokach Django lub widokach opartych na DRF, można przypisać klasy throttlingu do odpowiednich widoków lub widoków klasowych. Działa to poprzez przypisanie listy klas throttlingu do atrybutu throttle_classes widoku. Możemy również ustawić różne klasy throttlingu dla różnych metod HTTP (np. GET, POST, itp.).

Przetwarzanie żądań: Kiedy żądanie dochodzi do widoku, framework DRF sprawdza klasy throttlingu przypisane do tego widoku. Jeśli zostaną spełnione limity określone w klasach throttlingu, żądanie zostaje przetworzone i zwracana jest odpowiedź. W przeciwnym przypadku, gdy żądanie przekracza limity, zostaje zwrócony błąd o przekroczeniu limitu (np. kod statusu HTTP 429 - Too Many Requests).

Dzięki mechanizmowi throttlingu, Django daje możliwość kontroli nad częstotliwością żądań i zapewnia ochronę aplikacji przed nadmiernym użyciem zasobów. Może to pomóc w utrzymaniu stabilności, bezpieczeństwa i wydajności serwera, szczególnie w przypadku popularnych aplikacji internetowych z dużą liczbą użytkowników lub publicznych API.
- #### Skad wiadomo jaki uzytkownik ma adres IP?
Throttling w kontekście adresu IP działa w taki sposób, że serwer, na którym działa aplikacja, identyfikuje adres IP, z którego pochodzi żądanie, aby kontrolować częstotliwość i limit dostępu dla danego adresu IP.

Kiedy klient wysyła żądanie do serwera, serwer odczytuje adres IP klienta z nagłówka żądania HTTP. Adres IP zawarty w nagłówku żądania informuje serwer, z jakiego źródła pochodzi żądanie.
Informacje o adresie IP klienta są dostępne w obiekcie request przekazywanym do widoku lub widoku klasowego w Django. Można odczytać adres IP klienta za pomocą request.META['REMOTE_ADDR'] lub request.META.get('HTTP_X_FORWARDED_FOR', ''), uwzględniając różne nagłówki w przypadku, gdy żądanie przechodzi przez serwery pośredniczące lub proxy.

- #### Gdzie zapisywane sa adresy IP?
Adres IP klienta może być zapisywany w bazie danych, w pamięci podręcznej (cache) lub innym mechanizmie przechowywania stanu. W przypadku Django, można wykorzystać modele i tabele w bazie danych do przechowywania adresów IP i ich powiązanych informacji, takich jak liczba żądań i czas ostatniego żądania.