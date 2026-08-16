from flask import Flask

# Create Flask application
app = Flask(__name__)

# Home Page Route
@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberShield</title>
        <style>
            body{
                font-family: Times New Roman , sans-serif;
                background:#f5f7fa;
                text-align:center;
                margin-top:100px;
            }
            h1{
                color:#0b5ed7;
            }
            p{
                font-size:18px;
            }
            .card{
                width:60%;
                margin:auto;
                padding:30px;
                background:white;
                border-radius:10px;
                box-shadow:0px 0px 15px rgba(0,0,0,0.1);
            }
        </style>
    </head>

    <body>

        <div class="card">

            <h1>🛡️ CyberShield</h1>

            <h2>Ransomware Analysis & Decryption System </h2>

            <p>
                Congratulations! Your Flask backend is running successfully.
            </p>

            <hr>

            <p>
                This is the first version of your CyberShield application.
            </p>

        </div>

    </body>

    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)