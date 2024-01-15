from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import psycopg2
from flask_cors import CORS
import random
import string
import threading
import time
import datetime
from datetime import date
import re
import jwt
import os
import json
import pyotp
from flask_mail import Mail, Message
import json
import openai



app = Flask(__name__)
cors = CORS(app)




openai.api_key = os.environ["OPENAI_API_KEY"]




@app.route("/", methods=["GET"])
def index():
  return "API Online"


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=3000)
