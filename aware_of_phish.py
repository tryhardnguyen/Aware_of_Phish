# Created by: Nguyen Nguyen
# Created on: 2023-03-15
# Github: https://github.com/tryhardnguyen
"""
This is a command line program that make analyzing phishing emaiils much easier.
By reading in the emails(.eml) you provided, and spit out the emails information pertaining to the email.
Futhermore, this program launch OSINT website for you so, you don't have to go through the hassle of opening your browser
and going to the website yourself.
"""

import sys
import os
from rich.console import Console
from rich.table import Table
from rich.style import Style
import webbrowser

# Global variables
console = Console()

def clear_terminal():
    os.system('cls' if os.name=='nt' else 'clear')

def is_email(path_to_email):
    import binascii
    #We are going to check if the user provided an email using file signature header.
    with open(path_to_email, 'rb') as file:
        email_content = file.read()
    #Turn the email binary to hex
    hex_data = binascii.hexlify(email_content)
    # Check the file signature via email header using regex
    import re
    headers = ["52657475726e2d506174683a","44656c6976657265642d546f3a","46726f6d3a","546f","44617465"] #Return-Path:, Delivered-To:, From:, To:, Date:
    # Check for each header in hex and if one is found, then the file is a email.
    for header in headers:
        if re.search(header, str(hex_data)):
            return True
            break
        else:
            return False

def primary_menu():
    _TITLE="AWARE OF PHISH"
    _columns = ["Choice", "Description"]
    _rows = {
        "1": "Email Information",
        "2": "Get URL",
        "3": "Get attachment hash (256)",
        "4": "Download attachment",
        "5": "OSINT",
    }
    table = Table(
        title=_TITLE, 
        title_style=Style(color="green", bold=True),
        show_lines=True, 
        row_styles=[
            Style(color="#000000", bgcolor="#709845", bold=True), 
            Style(color="#000000", bgcolor="#642d8a", bold=True), 
            Style(color="#000000", bgcolor="#f2f2c1", bold=True),
            ]
        )
    for column in _columns:
        table.add_column(column, header_style="magenta")
    for row in _rows:
        table.add_row(row, _rows[row])
    console.print(table)

def email_information_table():
    _TITLE="Email Information"
    _columns = ["Choice", "Description"]
    _rows = {
        "1": "Return-Path",
        "2": "Authentication-Results",
        "3": "Received",
        "4": "From",
        "5": "Received-SPF",
        "6": "DKIM-Signature",
        "7": "Body",
    }
    # Create the Table
    table = Table(
            title=_TITLE, 
            title_style=Style(color="green", bold=True), 
            show_lines=True, 
            row_styles=[
                Style(color="#000000", bgcolor="#0080FF", bold=True),
                Style(color="#000000", bgcolor="#FFA500", bold=True), 
                Style(color="#000000", bgcolor="#008000", bold=True),
            ]
    )
    for column in _columns:
        table.add_column(column, header_style="magenta")
    for row in _rows:
        table.add_row(row, _rows[row])
    console.print(table)

def osint_table():
    _TITLE="OSINT Sites"
    _columns = ["Choice", "Description"]
    _rows = {
        "1": "Open VirusTotal",
        "2": "Open AbuseIPDB",
        "3": "Open Cisco Talos",
        "4": "Open MxToolbox",
    }
    table = Table(
        title=_TITLE, 
        title_style=Style(color="green", bold=True),
        show_lines=True, 
        row_styles=[
            Style(color="#000000", bgcolor="#709845", bold=True), 
            Style(color="#000000", bgcolor="#642d8a", bold=True), 
            Style(color="#000000", bgcolor="#f2f2c1", bold=True),
            ]
        )
    for column in _columns:
        table.add_column(column, header_style="magenta")
    for row in _rows:
        table.add_row(row, _rows[row])
    console.print(table)
    
def get_email_data(choice, email_path):
    import re
    import email
    from email import policy
    from email.parser import BytesParser
    
    menu_choice = {
        "1": "Return-Path",
        "2": "Authentication-Results",
        "3": "Received",
        "4": "From",
        "5": "Received-SPF",
        "6": "DKIM-Signature",
        "7": "Body",
    }
    
    # Open the .eml file and read its contents as bytes
    with open(email_path, 'rb') as file:
        email_content = file.read()
    # Parse the email message using BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    
    if choice == "1":
        return_path = msg["Return-Path"]
        clear_terminal()
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output", style="bold underline green")
        console.print(f"[cyan]{return_path}[/cyan]")
        
    elif choice == "2":
        authentication_results = msg.get_all("Authentication-Results")
        clear_terminal()
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output", style="bold underline green")
        console.print(f"[cyan]{authentication_results}[/cyan]")
        
    elif choice == "3": #Received
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output:", style="bold underline green")
        recieved_headers = msg.get_all("Received")
        print("The order is based on the path from the sender to the receiver.")
        print(f"Top being close to the receiver. Bottom being close to the sender.")
        console.print()
        for hop, header in enumerate(recieved_headers, start=1):
            console.print(f"Hop: {hop}")
            console.print(f"Header: {header}")
            console.print()
            
    elif choice == "4": #From
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output:", style="bold underline green")
        from_headers = msg.get_all("From")
        print(from_headers[0])
        
    elif choice == "5": #Received-SPF
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output:", style="bold underline green")
        received_spf = msg.get_all("Received-SPF")
        print(received_spf[0])
        
    elif choice == "6": #DKIM-Signature
        recieved_headers = msg.get_all("DKIM-Signature")
        if recieved_headers == None:
            print("No DKIM-Signature header found in the email")
        else:
            print(recieved_headers[0].replace(" ", ""))
    
    elif choice == "7": #Body
        # Extract the body of the email
        if msg.is_multipart():
            # If the email has multiple parts, iterate through them and find the text/plain part
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    email_body = part.get_payload(decode=True).decode()
        else:
            # If the email has only one part, simply extract the text
            if part.get_content_type() == 'text/html':
                email_body = part.get_payload(decode=True).decode()
        # Print the body of the email
        console.print(f"Output:", style="bold underline green")
        console.print(email_body)

def attachment(choice, email_path):
    import re
    import email
    from email import policy
    from email.parser import BytesParser
    
    with open(email_path, 'rb') as file:
        email_content = file.read()
    # Parse the email message using BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    
    attachment_found = False #(Default)
    # Extract the attachment(s) from the email
    for part in msg.walk():
        # Check if the part is an attachment
        if part.get_content_disposition() == 'attachment':
            attachment_found = True
            # Get the filename of the attachment
            filename = part.get_filename()
            # Get the content of the attachment
            content = part.get_payload(decode=True)
            if choice == "3":
                #Library used for encryption
                import hashlib
                # Hash the attachment content using SHA-256
                hash_object = hashlib.sha256(content)
                hex_dig = hash_object.hexdigest()
                console.print(f"Attachment {filename} has SHA-256 hash: [cyan]{hex_dig}[/cyan]")
            elif choice == "4": #Save the attachment to disk
                console.print(f"Disclaimer: Before we start, please make sure you download the attachment in a isolated environment.")
                console.print(f"I'm not responsible for any loss or damage caused by the attachment.")
                console.print(f"If you have been warned")
                console.print(f"[red]==================================================[/red]")
                print()
                save_or_no = input("Are you in a safe isolated environment to save the attachment? [y/n] ")
                print()
                if save_or_no.lower() == "y":
                            while True:
                                try:
                                    place_to_save = input(f"Where would you like to save the attachment ({filename})?: ")
                                    print()
                                    with open(f"{place_to_save}/{filename}", "wb") as file:
                                        file.write(content)
                                    print()
                                    console.print(f"Attachment {filename} has been saved to: [cyan]{place_to_save}[/cyan]")
                                    break
                                except FileNotFoundError:
                                    console.print(f"[red]Invalid File Location, Try again! [/red]")
                elif save_or_no.lower() == "n":
                    break
    if attachment_found == False:
        console.print("Sorry, no attachment was found in the email", style="bold red")

def get_url(email_path):
    import re
    import email
    from email import policy
    from email.parser import BytesParser
    
    with open(email_path, 'rb') as file:
        email_content = file.read()
    # Parse the email message using BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    
    # Go to the body of the email
    for part in msg.walk():
        #Go to the 
        if part.get_content_type() == 'text/html':
            email_body = part.get_payload(decode=True).decode()
    # Then get the the URL inside the body by searching for <a href="...">...</a>
    url = re.findall(r"<a\shref=\"https?:\/\/[\w\W]+<\/a>", email_body)
    #Since find.all return a list. Empty list represent that it found no URL
    if len(url) == 0:
        console.print("Sorry, no URL was found in the email", style="bold red")
    else:
        console.print(f"Output: ",style="bold underline green")
        console.print(f"[cyan]{url[0]}[/cyan]")
    
def main():
    # Make sure that the email that the user provided is a valid.'
    show_menu = True
    
    while True:
        email_path = input("Please enter the path of the email (For example: /home/user/email.eml): or 'q' to quit: ")
        if email_path == "q":
            show_menu = False
            break
        try:
            if is_email(email_path):
                break
        except FileNotFoundError as e:
            console.print("File is not Found", style="red")
        else:
            console.print("Invalid File Type", style="red")
    if show_menu:
        primary_menu()
        while True:
            choice = input("Please enter your choice ('q' to quit): ")
            print()
            if choice == "q":
                break
            elif choice == "1":
                while True:
                    email_information_table()
                    sub_choice = input("Please enter your choice ('q' to quit): ")
                    print()
                    if sub_choice == "q":
                        clear_terminal()
                        break
                    elif sub_choice == "1": # Return-Path
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "2": # Authentication-Result
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "3": # Received
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "4": # From
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "5": # Received-SPF
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "6": # DKIM-Signature
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "7": # Body
                        get_email_data(sub_choice, email_path)
                        print()
            elif choice == "2": # Get URL (If it exists)
                get_url(email_path)
                print()
            elif choice == "3": # Get attachment hash (SHA-256)
                attachment(choice, email_path)
                print()
            elif choice == "4": # Download attachment
                attachment(choice, email_path)
                print()
            elif choice == "5": # OSINT
                while True:
                    osint_table()
                    sub_choice = input("Please enter your choice ('q' to quit): ")
                    print()
                    match sub_choice:
                            case "q":
                                break
                            case "1": #virustotal
                                console.print("Press Enter on the terminal to continue....", style="bold blue")
                                print()
                                webbrowser.open("https://www.virustotal.com/gui/home/search")
                            case "2": #abuseipdb
                                console.print("Press Enter on the terminal to continue....", style="bold blue")
                                print()
                                webbrowser.open("https://www.abuseipdb.com/")
                            case "3": #ciscotalos
                                console.print("Press Enter on the terminal to continue....", style="bold blue")
                                print()
                                webbrowser.open("https://www.talosintelligence.com/")
                            case "4": #mxtoolbox
                                console.print("Press Enter on the terminal to continue....", style="bold blue")
                                print()
                                webbrowser.open("https://mxtoolbox.com/EmailHeaders.aspx")
                            case _:
                                console.print("Invalid Choice.....", style="bold red")
                                print()
                            
                    
            
            primary_menu()

if __name__ == '__main__':
    main()