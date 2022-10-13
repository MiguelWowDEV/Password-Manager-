from cryptocode import *
from passlib.context import CryptContext
import passlib.handlers.pbkdf2
from getpass4 import getpass
import os
from cryptocode import decrypt, encrypt
from dotenv import load_dotenv, set_key
from email_validator import EmailNotValidError, validate_email
import json
import click

""" Programa para gestión de contraseñas - APP CLI (Beta-v: 1.0)"""

load_dotenv(".env")

########## FUNCIONES DEL PROGRAMA #####################
pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)

def encrypt_password(password):
    return pwd_context.hash(password)


def check_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)

def check_security(password, phrase):

    if check_encrypted_password(password, os.getenv("PASSWORD_HASH")) and check_encrypted_password(phrase, os.getenv("PHRASE")):
        return True

    else: 
        return False

########## Función Principal ##########################
@click.group()
def main():
    pass

@click.command()
@click.confirmation_option()
@click.password_option()
def new_password(password):

    """ Cambiar la contraseña actual """

    after_pd = getpass("\nAfter password: ")
    user_phrase = getpass("\nPhrase: ")

    #Sistema de seguridad para establecer una nueva contraseña
    if check_encrypted_password(after_pd, user_phrase):

        #Guardamos la nueva contraseña
        set_key(".env", "PASSWORD_HASH",encrypt_password(password))
        click.echo("\nNueva contraseña establecida!")

    else:
        click.echo("\nContraseña incorrecta!")
        return

########## Establecer sistema de seguridad ######################
@click.command()
@click.password_option()
def add_security(password):

    """ Establecer un sistema de seguridad """

    set_key(".env", "PASSWORD_HASH",encrypt_password(password))

    #Agregamos la frase requerida para el sistema de seguridad
    p_save = getpass("\nPhrase security: ")
    set_key(".env", "PHRASE",encrypt_password(p_save))

    click.echo("\nSistema de seguridad establecido!")

########## Agregar contraseña #########################
@click.command()
@click.option("-e", "--email", prompt="Email", type=str, required=True)
@click.option("-w", "--web", prompt="Web o tipo", type=str, required=True)
@click.password_option()
def add_account(email, password, web):
    """ Guardar la contraseña junto a una cuenta """

    #Comprobamos si el email es valido
    try:
        validate_email(email)

    except EmailNotValidError:
        click.echo("\nError: Email no valido...")
        return

    #SISTEMA DE SEGURIDAD
    pd_user = getpass("\nPassword security: ")
    phrase = getpass("Phrase security: ")

    if not check_security(pd_user, phrase):
        click.echo("\nSeguridad incorrecta!")
        return

    #Abrimos la base de datos
    with open("mn_pd.json", "r") as file:
        content_pd = json.load(file)

    #Encriptamos la contraseña
    hash = encrypt(password, phrase)

    #Diccionario de la contraseña añadida
    dict_pd = {"type": web.lower(), "email": email.lower(), "password": hash}

    #Revisamos si la base de datos esta vacía
    if content_pd:    
        for p in content_pd:

            if dict_pd["email"] == p["email"] and dict_pd["type"] == p["type"] :
                click.echo("\nYa se registro esa cuenta...")
                return

    #Añimos a la lista
    content_pd.append(dict_pd)

    #Actualizamos base de datos
    with open("mn_pd.json", "w") as file:
        update_content = json.dumps(content_pd, indent=4)
        file.write(update_content)

    click.echo("\nContraseña añadida!")

@click.command()
@click.confirmation_option()
def list_accounts():
    """ Mostrar todas las cuentas guardadas """

    #SISTEMA DE SEGURIDAD
    pd_user = getpass("\nPassword security: ")
    phrase = getpass("Phrase security: ")

    if not check_security(pd_user, phrase):
        click.echo("\nSeguridad incorrecta!")
        return

    #Leemos base de datos
    with open("mn_pd.json", "r") as file:
        accounts = json.load(file)

        for c in accounts:
            #Contraseña desencriptada
            password = decrypt(c["password"], phrase)
            
            #Mostramos los datos
            click.echo("\n-----------------------------")
            click.echo(f"Tipo: {c['type']}\nCorreo: {c['email']}\nContraseña: {password}")
            click.echo("\n-----------------------------")

""" Agregamos este comando para que el usuario
establezca primero un sistema de seguridad
 """
main.add_command(add_security)

if __name__ == "__main__":

    """ Esto ayudara a el usuario a establecer una nueva contraseña si quiere
    y evitar que se modifique todo el sistema de seguridad borrando el comando
     """
    if os.getenv("PASSWORD_HASH") != "0":
        
        main.add_command(new_password)
        main.add_command(add_account)
        main.add_command(list_accounts)
        del main.commands["add-security"]

    main()