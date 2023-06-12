# Projet de Crypto APPING2 Promo 2024

Ce répertoire contient deux fichiers utilisés pour démontrer
un scénario de certificat d'attributs (cas d'une banque).

Les scripts doivent être exécutés dans cet ordre :
* python3 certification_authority.py
* python3 request_access.py

Le premier script va premièrement créer un certificat auto-signé pour
l'autorité de certification (CA), pour ensuite créer trois certificats d'utilisateurs.
Un des certificats n'aura pas d'attributs lui permettant d'accéder au site de
transaction de la banque, un autre aura les attributs nécessaires,
et le dernier aura un accès révoqué.

Le deuxième script contient une fonction qui pourrait essentiellement
être utilisée par le site de la banque pour contrôler l'accès à ses ressources.
La fonction affiche des messages différents dépendant des attributs présentés
par le certificat de l'utilisateur demandant accès à une ressource.
