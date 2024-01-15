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
bcrypt = Bcrypt()





openai.api_key = os.environ["OPENAI_API_KEY"]


db_params = {
    'host': hostsecret,
    'port': portsecret,
    'user': usersecret,
    'password': passwordsecret,
    'database': databasesecret
}

mail_params = {
    'email': mailsecret,  # Your email address for sending OTP
    'password': mailpasswordsecret,  # Your email password
    'server': servergmailsecret,  # Change based on your email provider
    'port': 587,
}

otp_expiry_seconds = 300  # OTP validity period in seconds



users = []
profiles = []
polls = []
surveys = []


def get_db_connection():
  try:
    connection = psycopg2.connect(**db_params)
    return connection
  except Exception as e:
    print(f"Error: Unable to connect to the database. {str(e)}")
    return None


mail = Mail(app)


def generate_otp():

  totp = pyotp.TOTP(otp_secret_key, interval=otp_expiry_seconds)
  return totp.now()


def send_otp(email, otp):
  msg = Message('Your OTP for PollVault',
                sender='your-email@gmail.com',
                recipients=[email])
  msg.body = f'Your OTP is: {otp}'
  try:
    mail.send(msg)
    print(f"OTP sent to {email}")
    return True
  except Exception as e:
    print(f"Error sending OTP: {str(e)}")
    return False


def store_otp_in_database(email, otp):

  connection = psycopg2.connect(**db_params)
  cursor = connection.cursor()

  try:
    cursor.execute("INSERT INTO otps (email, otp) VALUES (%s, %s)",
                   (email, otp))
    connection.commit()
  except Exception as e:
    print(f"Error storing OTP in the database: {str(e)}")
    connection.rollback()
  finally:
    cursor.close()
    connection.close()


def verify_otp_in_database(email, otp):
  # Verify the OTP in the database
  connection = psycopg2.connect(**db_params)
  cursor = connection.cursor()

  try:
    cursor.execute("SELECT * FROM otps WHERE email = %s AND otp = %s",
                   (email, otp))
    result = cursor.fetchone()

    if result:
      return True
    else:
      return False
  except Exception as e:
    print(f"Error verifying OTP in the database: {str(e)}")
    return False
  finally:
    cursor.close()
    connection.close()


@app.route("/", methods=["GET"])
def index():
  return "API Online"


@app.route('/signup', methods=['POST'])
def sign_up():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  email = data.get('email')
  password = data.get('password')

  if not email or not password:
    return jsonify({
        'status': 'error',
        'error_content': 'Email and password are required'
    }), 400

  connection = get_db_connection()
  if connection:
    try:
      cursor = connection.cursor()

      cursor.execute("SELECT * FROM users WHERE email = %s", (email, ))
      existing_user = cursor.fetchone()
      if existing_user:
        return jsonify({
            'status': 'error',
            'error_content': 'Email already exists in the database'
        }), 400

      hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

      cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)",
                     (email, hashed_password))
      connection.commit()

      return jsonify({'status': 'success'}), 200
    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status': 'error',
          'error_content': 'Failed to register user'
      }), 500
    finally:
      cursor.close()
      connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/resetpassword', methods=['POST'])
def reset_password():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  email = data.get('email')
  password = data.get('password')

  if not email or not password:
    return jsonify({
        'status': 'error',
        'error_content': 'Email and password are required'
    }), 400

  connection = get_db_connection()
  if connection:
    try:
      cursor = connection.cursor()

      cursor.execute("SELECT * FROM users WHERE email = %s", (email, ))
      user = cursor.fetchone()
      if not user:
        return jsonify({
            'status': 'error',
            'error_content': 'Email doesn\'t exist in the database'
        }), 400

      if bcrypt.check_password_hash(user[2], password):
        return jsonify({
            'status': 'error',
            'error_content': 'This is the current password'
        }), 400

      hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
      cursor.execute("UPDATE users SET password = %s WHERE email = %s",
                     (hashed_password, email))
      connection.commit()

      return jsonify({'status': 'success'}), 200
    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status': 'error',
          'error_content': 'Failed to reset password'
      }), 500
    finally:
      cursor.close()
      connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


def validate_access_token(access_token):
  try:
    # Decode the access token
    decoded_token = jwt.decode(access_token,
                               jwtsecret,
                               algorithms=['HS256'])

    # Check if the token is not expired
    if datetime.datetime.utcnow() < datetime.datetime.utcfromtimestamp(
        decoded_token['exp']):
      return {
          'user_id': decoded_token['user_id'],
          'email': decoded_token['email']
      }
  except jwt.ExpiredSignatureError:
    pass  # Token has expired
  except jwt.InvalidTokenError:
    pass  # Invalid token or signature

  return None


def update_question_full(outline_id, connection):
    print("question full function")
    try:
        # Create a cursor
        cursor = connection.cursor()

        # Fetch rows based on outline_id
        query = "SELECT id, question_text, question_type, options FROM outline WHERE outline_id = %s"
        cursor.execute(query, (outline_id,))
        rows = cursor.fetchall()

        for row in rows:
            id, question_text, question_type, options = row

            print(f"Processing row: {row}")

            if question_type == 'MCQ' and options:
                # If question_type is 'MCQ' and options exist, create question_full accordingly
                formatted_options = "\n".join(f"{chr(97 + i)}. {option}" for i, option in enumerate(options))
                question_full = f"{question_text}\n {formatted_options}"
                print(f"Question_full for MCQ: {question_full}")
            else:
                # If question_type is not 'MCQ' or options don't exist, use question_text only
                question_full = question_text
                print(f"Question_full for non-MCQ: {question_full}")

            # Update the row with the new question_full using the unique id
            update_query = "UPDATE outline SET question_full = %s WHERE id = %s"
            cursor.execute(update_query, (question_full, id))

        # Commit the changes
        connection.commit()

    finally:
        # Close the cursor
        cursor.close()



@app.route('/signin', methods=['POST'])
def sign_in():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  email = data.get('email')
  password = data.get('password')

  if not email or not password:
    return jsonify({
        'status': 'error',
        'error_content': 'Email and password are required'
    }), 400

  connection = get_db_connection()
  if connection:
    try:
      cursor = connection.cursor()

      cursor.execute("SELECT * FROM users WHERE email = %s", (email, ))
      user = cursor.fetchone()
      if not user:
        return jsonify({
            'status': 'error1',
            'error_content': 'Email doesn\'t exist in the database'
        }), 401

      if not bcrypt.check_password_hash(user[2], password):
        return jsonify({
            'status': 'error2',
            'error_content': 'Wrong password'
        }), 401

      # Generate JWT token
      token_payload = {
          'user_id': user[0],
          'email': user[1],
          'exp': datetime.datetime.utcnow() +
          datetime.timedelta(days=1)  # Token expiration (adjust as needed)
      }

      try:
        jwt_token = jwt.encode(token_payload,
                               jwtsecret,
                               algorithm='HS256')
        print(f"JWT Token: {jwt_token}")
        jwtd = jwt_token.decode('utf-8')
        # Insert data into the 'signedin' table
        cursor.execute(
            "INSERT INTO signedin (email, jwt_token) VALUES (%s, %s)",
            (email, jwtd))
        connection.commit()
      except Exception as e:
        print(f"Error encoding JWT: {str(e)}")

      # Return the token in the response
      return jsonify({
          'status': 'success',
          'token': jwt_token.decode(
              'utf-8')  # Convert bytes to string for JSON serialization
      }), 200
    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status': 'error',
          'error_content': 'Failed to sign in'
      }), 500
    finally:
      cursor.close()
      connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/profilesetup', methods=['POST'])
def profile_setup():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  jwt_token = request.headers.get('JWTToken')

  if not jwt_token:
    return jsonify({
        'status': 'error',
        'error_content': 'JWT token is required'
    }), 401

  # Validate the access token (implement your token validation logic)
  user = validate_access_token(jwt_token)

  if not user:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid JWT token'
    }), 401

  data = request.get_json()
  #email = data.get('email')
  salutation = data.get('salutation')
  first_name = data.get('firstname')
  last_name = data.get('lastname')
  industry = data.get('industry')
  location = data.get('location')
  phone = data.get('phone')

  #if not email:
  #  return jsonify({
  #      'status': 'error',
  #      'error_content': 'Email is required'
  #  }), 400

  connection = get_db_connection()
  if connection:
    try:
      cursor = connection.cursor()

      #cursor.execute("SELECT * FROM users WHERE email = %s", (email, ))
      #existing_user = cursor.fetchone()
      #if not existing_user:
      #  return jsonify({
      #      'status': 'error',
      #      'error_content': 'User not found'
      #  }), 404

      cursor.execute("SELECT * FROM profiles WHERE phone = %s", (phone, ))
      existing_phone = cursor.fetchone()
      if existing_phone:
        return jsonify({
            'status': 'error',
            'error_content': 'Phone number already in the database'
        }), 400

      cursor.execute(
          """
                INSERT INTO profiles (salutation, firstname, lastname, industry, location, phone)
                VALUES (%s, %s, %s, %s, %s, %s)

            """,
          (salutation, first_name, last_name, industry, location, phone))
      connection.commit()

      return jsonify({'status': 'success'}), 200
    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status': 'error',
          'error_content': 'Failed to set up user profile'
      }), 500
    finally:
      cursor.close()
      connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


# Dictionary to store outline IDs and their creation times
outline_creation_times = {}


def generate_outline_id(cursor):
  while True:
    outline_id = ''.join(random.choices(string.digits, k=6))

    cursor.execute("SELECT * FROM polls WHERE outline_id = %s", (outline_id, ))
    existing_poll = cursor.fetchone()

    if not existing_poll:
      return outline_id


# Create a function to generate questions and a random code using GPT-3.5 Turbo
def generate_questions(prompt):
  response = openai.ChatCompletion.create(
      model="gpt-4-1106-preview",
      messages=[
          {
              "role":
              "system",
              "content":
              "You are a helpful assistant that generates questions,type(MCQ or Free Text) from the given prompt and replies it in a json format and even if the content includes '\n' dont include it in the json response since we dont need it. It must reply in this format eg. : 'numberofquestions': len(questions)(2 in this case),'time': appropriate time for answering the entire survey,'questions': (( 'question1': ('question': 'What is your favorite color?','type': 'MCQ','options': ['Red', 'Blue', 'Green']),('question2': ('question': 'What is your favorite programming language?','type': 'free text')) So understand this and reply it in a json format accordingly",
          },
          {
              "role": "user",
              "content": prompt
          },
      ],
  )
  generated_questions = response['choices'][0]['message']['content']
  return generated_questions


# Function to create the outline with actual generated questions
def create_outline(outline_id, connection, title, document):
  try:
    with connection.cursor() as cursor:
      # Add debug print statements to check the content of the 'document'
      print("Document:", document)
      generated_questions = generate_questions(document)
      print("Raw Response:", generated_questions)

      # Use regular expression to extract text between backticks and remove "json"
      match = re.search(r'```json([^`]+)```', generated_questions)

      if match:
        required_format = match.group(1)
        print(required_format)
      else:
        print("No match found")

      # Parse the generated_questions string as JSON
      generated_questions_response = json.loads(required_format)
      print("Parsed Response:", generated_questions_response)
      questions_data = generated_questions_response.get("questions", [])

      print("Questions Data:", questions_data)

      # Extract overall details
      number_of_questions = generated_questions_response.get(
          "numberofquestions", 0)
      survey_time = generated_questions_response.get("time", "unknown")

      for index, question_data in enumerate(questions_data, start=1):
        question_key = f"question{index}"
        print(f"Question {index}")

        question_text = question_data[question_key]['question']
        print(f"Question Text: {question_text}")

        question_type = question_data[question_key]['type']
        print(f"Question Type: {question_type}")

        options = json.dumps(question_data[question_key].get('options', []))
        print(f"Options: {options}")
        print()

        cursor.execute(
            """
                  INSERT INTO outline (outline_id, title, question_number, question_text, question_type, branching, options, importance, required, instruction, dynamic_followup, objective, max_no_of_questions, keywords_to_probe, things_to_avoid, example_questions, status)
                  VALUES (%s, %s, %s, %s, %s, FALSE, %s, 'normal', TRUE, NULL, FALSE, NULL, %s, NULL, NULL, NULL, 'created')
                  """, (outline_id, title, index, question_text, question_type,
                        options, number_of_questions))

      connection.commit()

    

  except Exception as e:
    print(f"Error creating outline: {str(e)}")
  finally:
    pass
    


# Function to update poll status
def update_poll_status(outline_id, connection, title, document):
    # Simulate a delay of 1 minute before changing the status to 'created'
    time.sleep(5)

    cursor = connection.cursor()
    try:
        create_outline(outline_id, connection, title, document)
        update_question_full(outline_id, connection)

        cursor.execute(
            "UPDATE polls SET status = 'created' WHERE outline_id = %s",
            (outline_id, ))
        connection.commit()

    except Exception as e:
        print(f"Error updating poll status: {str(e)}")
    finally:
        cursor.close()
        if connection:
            connection.close()


# Your existing upload_poll route
@app.route('/uploadpoll', methods=['POST'])
def upload_poll():
  api_secret = request.headers.get('APISECRET')
  jwt_token = request.headers.get('JWTToken')

  if not jwt_token:
    return jsonify({
        'status': 'error',
        'error_content': 'JWT token is required'
    }), 401

  # Validate the access token (implement your token validation logic)
  user = validate_access_token(jwt_token)

  if not user:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid JWT token'
    }), 401

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  title = data.get('title')
  goal = data.get('goal')
  document = data.get('document')
  end_after_date = data.get('endafterdate')
  end_after_responses = data.get('endafterresponses')
  #email = data.get('email')
  geography = data.get('geography')
  education = data.get('education')
  industry = data.get('industry')
  visibility = data.get('visibility')

  #if not title or not email:
  #  return jsonify({
  #      'status': 'error',
  #      'error_content': 'Title and email are required'
  #  }), 400

  connection = get_db_connection()
  if connection:
    try:
      cursor = connection.cursor()

      #cursor.execute("SELECT * FROM users WHERE email = %s", (email, ))
      #user = cursor.fetchone()
      #if not user:
      #  return jsonify({
      #      'status':
      #      'error',
      #      'error_content':
      #      'User with the provided email does not exist'
      #  }), 404

      outline_id = generate_outline_id(cursor)

      cursor.execute(
          """
                INSERT INTO polls (outline_id, title, goal, document, endafterdate, endafterresponses,  geography, education, industry, visibility, status, jwt_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s)
                """, (outline_id, title, goal, document, end_after_date,
                      end_after_responses, geography, education, industry,
                      visibility, 'processing', jwt_token))

      connection.commit()

      # Store the creation time of the outline ID for later status update
      outline_creation_times[outline_id] = time.time()

      # Start a separate thread to update the status after 2 minutes
      threading.Thread(target=update_poll_status,
                       args=(outline_id, connection, title, document)).start()

      # Return the immediate response
      return jsonify({
          'status': 'success',
          'outline_id': outline_id,
          'processing_status': 'processing'
      }), 200
    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status': 'error',
          'error_content': 'Failed to create poll'
      }), 500
    finally:
      if cursor:
        cursor.close()
  else:
    return jsonify({
        'status': 'error',
        'error_content': 'Unable to connect to the database'
    }), 500


@app.route('/getoutline', methods=['POST'])
def get_outline():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  jwt_token = request.headers.get('JWTToken')

  if not jwt_token:
    return jsonify({
        'status': 'error',
        'error_content': 'JWT token is required'
    }), 401

  # Validate the access token (implement your token validation logic)
  user = validate_access_token(jwt_token)

  if not user:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid JWT token'
    }), 401

  data = request.get_json()
  outline_id = data.get('idoutline')

  if not outline_id:
    return jsonify({
        'status': 'error',
        'error_content': 'Contents not filled'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Fetch data from the outline table based on outline_id
        cursor.execute(
            """
                    SELECT * FROM outline
                    WHERE outline_id = %s
                    ORDER BY question_number
                    """, (outline_id, ))
        outline_data = cursor.fetchall()

        if outline_data:
          # Get the column names from cursor.description
          column_names = [desc[0] for desc in cursor.description]

          # Construct the response JSON with the fetched outline data
          response_json = {
              'outline': {
                  'numberofquestions': len(outline_data),
                  'questions': [],
                  'time': '10 minutes',
                  'title': outline_data[0][column_names.index('title')],
                  'status': outline_data[0][column_names.index('status')],
                  'outline_id':
                  outline_data[0][column_names.index('outline_id')],
                  'id': outline_data[0][column_names.index('id')],
              },
              'outlinestatus': outline_data[0][column_names.index('status')],
              'status': 'success'
          }

          # Iterate through fetched data and structure the questions
          for row in outline_data:
            if row[column_names.index('dynamic_followup')] == 'true':
              dfu = True
            else:
              dfu = False

            if row[column_names.index('required')] == 'true':
              dfr = True
            else:
              dfr = False

            question_data = {
                "question_number":
                row[column_names.index('question_number')],
                "branching":
                row[column_names.index('branching')],
                "question":
                row[column_names.index('question_full')],
                "type":
                row[column_names.index('question_type')],
                "importance":
                row[column_names.index('importance')],
                "required":
                dfr,
                "instruction":
                row[column_names.index('instruction')],
                "dynamic_followup":
                dfu,
                "objective":
                row[column_names.index('objective')],
                "max_no_of_questions":
                row[column_names.index('max_no_of_questions')],
                "keywords_to_probe":
                row[column_names.index('keywords_to_probe')],
                "things_to_avoid":
                row[column_names.index('things_to_avoid')],
                "example_questions":
                row[column_names.index('example_questions')],
                "allow_others":
                row[column_names.index('allow_others')],
                "max_no_of_choices":
                row[column_names.index('max_no_of_choices')],
                # Include other columns as needed
            }

            response_json['outline']['questions'].append(question_data)

          return jsonify(response_json), 200
        else:
          return jsonify({
              'status': 'error',
              'error_content': 'Outline ID does not exist'
          }), 404

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to fetch outline data. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/saveoutline', methods=['POST'])
def save_outline():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  jwt_token = request.headers.get('JWTToken')

  if not jwt_token:
    return jsonify({
        'status': 'error',
        'error_content': 'JWT token is required'
    }), 401

  # Validate the access token (implement your token validation logic)
  user = validate_access_token(jwt_token)
  if not user:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid JWT token'
    }), 401

  data = request.get_json()
  outline_data = data.get('outline')

  if not outline_data:
    return jsonify({
        'status': 'error',
        'error_content': 'Contents not filled'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Extract outline information
        title = outline_data.get('title')
        outline_id = outline_data.get('outline_id')
        status = outline_data.get('status')

        # Delete existing rows for the given outline_id
        cursor.execute("DELETE FROM outline WHERE outline_id = %s",
                       (outline_id, ))

        # Insert new rows into the outline table
        for question_data in outline_data.get('questions', []):
          cursor.execute(
              """
                        INSERT INTO outline (
                            title, question_number, importance, required, instruction,
                            dynamic_followup, objective, max_no_of_questions,
                            keywords_to_probe, things_to_avoid, example_questions,allow_others,max_no_of_choices,
                            question_text, question_type, branching, outline_id, status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
              (title, question_data.get('question_number'),
               question_data.get('importance', 'normal'),
               question_data.get('required',
                                 'TRUE'), question_data.get('instruction'),
               question_data.get('dynamic_followup',
                                 'FALSE'), question_data.get('objective'),
               question_data.get('max_no_of_questions'),
               question_data.get('keywords_to_probe'),
               question_data.get('things_to_avoid'),
               question_data.get('example_questions'),
               question_data.get('allow_others'),
               question_data.get('max_no_of_choices'),
               question_data['question'], question_data['type'],
               question_data.get('branching', 'FALSE'), outline_id, status))

        connection.commit()

        return jsonify({
            'status': 'success',
            'message': 'Outline saved successfully'
        }), 200

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to save outline. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/publishsurvey', methods=['POST'])
def publish_survey():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  jwt_token = request.headers.get('JWTToken')

  if not jwt_token:
    return jsonify({
        'status': 'error',
        'error_content': 'JWT token is required'
    }), 401

  # Validate the access token (implement your token validation logic)
  user = validate_access_token(jwt_token)
  if not user:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid JWT token'
    }), 401

  data = request.get_json()
  outline_data = data.get('outline')

  if not outline_data:
    return jsonify({
        'status': 'error',
        'error_content': 'Contents not filled'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Extract outline information
        title = outline_data.get('title')
        outline_id = outline_data.get('outline_id')
        status = outline_data.get('status')

        # Delete existing rows for the given outline_id
        cursor.execute("DELETE FROM outline WHERE outline_id = %s",
                       (outline_id, ))

        # Insert new rows into the outline table
        for question_data in outline_data.get('questions', []):
          cursor.execute(
              """
                        INSERT INTO outline (
                            title, question_number, importance, required, instruction,
                            dynamic_followup, objective, max_no_of_questions,
                            keywords_to_probe, things_to_avoid, example_questions,allow_others,max_no_of_choices,
                            question_full, question_type, branching, options, outline_id, status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s)
                        """,
              (title, question_data.get('question_number'),
               question_data.get('importance', 'normal'),
               question_data.get('required',
                                 'TRUE'), question_data.get('instruction'),
               question_data.get('dynamic_followup',
                                 'FALSE'), question_data.get('objective'),
               question_data.get('max_no_of_questions'),
               question_data.get('keywords_to_probe'),
               question_data.get('things_to_avoid'),
               question_data.get('example_questions'),
               question_data.get('allow_others'),
               question_data.get('max_no_of_choices'),
               question_data['question'], question_data['type'],
               question_data.get('branching', 'FALSE'),
               json.dumps(question_data.get('options',
                                            [])), outline_id, status))

        # Generate a unique 6-digit survey code
        survey_code = generate_unique_survey_code(cursor)

        # Insert into the published table
        cursor.execute(
            """
                    INSERT INTO published (outline_id, survey_code)
                    VALUES (%s, %s)
                    """, (outline_id, survey_code))

        connection.commit()

        return jsonify({
            'status': 'success',
            'message': 'Survey published successfully',
            'survey_code': survey_code
        }), 200

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to publish survey. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


def generate_unique_survey_code(cursor):
  # Generate a unique 6-digit survey code that doesn't exist in the published table
  while True:
    survey_code = ''.join(random.choices(string.digits, k=6))
    cursor.execute("SELECT COUNT(*) FROM published WHERE survey_code = %s",
                   (survey_code, ))
    count = cursor.fetchone()[0]
    if count == 0:
      return survey_code


@app.route('/responsequestions', methods=['POST'])
def response_questions():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  survey_code = data.get('survey_code')

  if not survey_code:
    return jsonify({
        'status': 'error',
        'error_content': 'Survey code not provided'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Check if survey code exists in the published table
        cursor.execute(
            "SELECT outline_id FROM published WHERE survey_code = %s",
            (survey_code, ))
        result = cursor.fetchone()

        if result:
          outline_id = result[0]

          # Fetch data from the outline table based on outline_id
          cursor.execute(
              """
                        SELECT * FROM outline
                        WHERE outline_id = %s
                        ORDER BY question_number
                        """, (outline_id, ))
          outline_data = cursor.fetchall()

          if outline_data:
            # Get the column names from cursor.description
            column_names = [desc[0] for desc in cursor.description]

            # Construct the response JSON with the fetched outline data
            response_json = {
                'outline': {
                    'numberofquestions': len(outline_data),
                    'questions': [],
                    'time': '10 minutes',
                    'title': outline_data[0][column_names.index('title')],
                    'status': outline_data[0][column_names.index('status')],
                    'outline_id':
                    outline_data[0][column_names.index('outline_id')],
                    'id': outline_data[0][column_names.index('id')],
                },
                'outlinestatus': outline_data[0][column_names.index('status')],
                'status': 'success'
            }

            # Iterate through fetched data and structure the questions
            for row in outline_data:
              question_data = {
                  "question_number":
                  row[column_names.index('question_number')],
                  "branching":
                  row[column_names.index('branching')],
                  "question":
                  row[column_names.index('question_text')],
                  "type":
                  row[column_names.index('question_type')],
                  "options":
                  row[column_names.index('options')],
                  "importance":
                  row[column_names.index('importance')],
                  "required":
                  row[column_names.index('required')],
                  "instruction":
                  row[column_names.index('instruction')],
                  "dynamic_followup":
                  row[column_names.index('dynamic_followup')],
                  "objective":
                  row[column_names.index('objective')],
                  "max_no_of_questions":
                  row[column_names.index('max_no_of_questions')],
                  "keywords_to_probe":
                  row[column_names.index('keywords_to_probe')],
                  "things_to_avoid":
                  row[column_names.index('things_to_avoid')],
                  "example_questions":
                  row[column_names.index('example_questions')],
                  # Include other columns as needed
              }

              response_json['outline']['questions'].append(question_data)

            return jsonify(response_json), 200
          else:
            return jsonify({
                'status': 'error',
                'error_content': 'Outline ID does not exist'
            }), 404

        else:
          return jsonify({
              'status': 'error',
              'error_content': 'Survey code not found'
          }), 404

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to fetch outline data. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/saveanswers', methods=['POST'])
def save_answers():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  survey_code = data.get('survey_code')
  question_data = data.get('question')
  answer_data = data.get('answer')

  if not survey_code or not question_data or not answer_data:
    return jsonify({
        'status': 'error',
        'error_content': 'Incomplete data provided'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Insert answer into the answers table
        cursor.execute(
            """
                    INSERT INTO answers (
                        survey_code, question_number, question, type, options, answer
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
            (survey_code, question_data.get('question_number'),
             question_data.get('question'), question_data.get('type'),
             json.dumps(question_data.get('options', [])), answer_data))

        connection.commit()

        return jsonify({
            'status': 'success',
            'message': 'Answers saved successfully'
        }), 200

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to save answers. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/sendotp', methods=['POST'])
def send_otp_route():
  email = request.json.get('email')

  otp = generate_otp()
  send_otp(email, otp)

  store_otp_in_database(email, otp)

  return jsonify({'status': 'success'}), 200


@app.route('/verifyotp', methods=['POST'])
def verify_otp_route():
  email = request.json.get('email')
  user_otp = request.json.get('otp')

  if verify_otp_in_database(email, user_otp):
    return jsonify({'status': 'success'}), 200
  else:
    return jsonify({'status': 'error', 'error_content': 'Wrong OTP'}), 401


# Get Outline Status
@app.route('/getoutlinestatus', methods=['POST'])
def get_outline_status():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  outline_id = data.get('idoutline')

  if not outline_id:
    return jsonify({
        'status': 'error',
        'error_content': 'Contents not filled'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Fetch outline status based on outline_id
        cursor.execute(
            """
                    SELECT status FROM outline
                    WHERE outline_id = %s
                    """, (outline_id, ))
        outline_status = cursor.fetchone()

        if outline_status:
          return jsonify({
              'status': 'success',
              'outlinestatus': outline_status[0]
          }), 200
        else:
          return jsonify({
              'status': 'error1',
              'error_content': 'Outline ID does not exist'
          }), 404

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to fetch outline status. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


@app.route('/getfirstquestion', methods=['POST'])
def get_first_question():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  survey_code = data.get('survey_code')

  if not survey_code:
    return jsonify({
        'status': 'error',
        'error_content': 'Survey code not provided'
    }), 400

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Check if survey code exists in the published table
        cursor.execute("SELECT * FROM published WHERE survey_code = %s",
                       (survey_code, ))
        result = cursor.fetchone()

        if result:
          # List of 7 example questions (4 MCQ and 3 Free text)
          example_questions = [
              {
                  "question_number": 1,
                  "question": "What is your favorite color?",
                  "type": "MCQ",
                  "options": ["Red", "Blue", "Green"]
              },
              {
                  "question_number": 2,
                  "question": "How often do you exercise?",
                  "type": "MCQ",
                  "options": ["Never", "Rarely", "Regularly"]
              },
              {
                  "question_number": 3,
                  "question": "What is your age?",
                  "type": "Free text",
                  "options": None
              },
              {
                  "question_number": 4,
                  "question": "Do you own a car?",
                  "type": "Free text",
                  "options": None
              },
              {
                  "question_number": 5,
                  "question": "Which programming language do you prefer?",
                  "type": "MCQ",
                  "options": ["Python", "Java", "JavaScript"]
              },
              {
                  "question_number": 6,
                  "question": "What is your occupation?",
                  "type": "Free text",
                  "options": None
              },
              {
                  "question_number": 7,
                  "question": "How many hours of sleep do you get?",
                  "type": "Free text",
                  "options": None
              },
          ]

          # Fetch the example question based on the question number
          question_data = next(q for q in example_questions
                               if q['question_number'] == 1)

          return jsonify({'status': 'success', 'question': question_data}), 200

        else:
          return jsonify({
              'status': 'error',
              'error_content': 'Survey code not found'
          }), 404

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to fetch question. Error: {str(e)}'
      }), 500

    finally:
      if connection:
        connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


predefined_questions = [
    {
        "question": "What is your favorite color?",
        "type": "MCQ",
        "options": ["Red", "Blue", "Green"]
    },
    {
        "question": "How often do you exercise?",
        "type": "MCQ",
        "options": ["Never", "Rarely", "Regularly"]
    },
    {
        "question": "What is your age?",
        "type": "Free Text"
    },
    {
        "question": "Which programming language do you prefer?",
        "type": "MCQ",
        "options": ["Python", "Java", "JavaScript"]
    },
    {
        "question": "What is your occupation?",
        "type": "Free Text"
    },
    {
        "question": "How many hours of sleep do you get?",
        "type": "Free Text"
    },
]


def get_next_question(current_question_number):

  next_question_number = current_question_number + 1

  if next_question_number > 6:
    return 'completed'

  next_question_data = predefined_questions[next_question_number - 1]

  return {
      "question_number": next_question_number,
      "question": next_question_data["question"],
      "type": next_question_data["type"],
      "options": next_question_data.get("options", None),
  }


@app.route('/savegetnextquestion', methods=['POST'])
def save_get_next_question():
  api_secret = request.headers.get('APISECRET')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  data = request.get_json()
  survey_code = data.get('survey_code')
  current_question_data = data.get('current_question')

  if not survey_code or not current_question_data:
    return jsonify({
        'status': 'error',
        'error_content': 'Incomplete data provided'
    }), 400

  # Save current question data to the answers table
  save_current_question_to_answers(survey_code, current_question_data)

  # Get the next question data
  next_question_data = get_next_question(
      current_question_data.get('question_number', 0))

  if next_question_data == 'completed':
    return jsonify({'status': 'completed'}), 200
  return jsonify({
      'status': 'success',
      'next_question': next_question_data
  }), 200


def save_current_question_to_answers(survey_code, current_question_data):
  # Extract data from the current question
  question_number = current_question_data.get('question_number')
  question_text = current_question_data.get('question')
  question_type = current_question_data.get('type')
  options = current_question_data.get('options')
  answer = current_question_data.get('answer')

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Insert current question data into the answers table
        cursor.execute(
            """
                    INSERT INTO answers (
                        survey_code, question_number, question, type, options, answer
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
            (survey_code, question_number, question_text, question_type,
             json.dumps(options or []), answer))

      connection.commit()

    except Exception as e:
      print(f"Error: {str(e)}")

    finally:
      if connection:
        connection.close()


@app.route('/getuseroutlines', methods=['GET'])
def get_user_outlines():
  api_secret = request.headers.get('APISECRET')
  jwt_token = request.headers.get('JWTToken')

  if api_secret != APISECRET:
    return jsonify({
        'status': 'error',
        'error_content': 'Invalid API secret'
    }), 401

  if not jwt_token:
    return jsonify({
        'status': 'error',
        'error_content': 'JWT token is required'
    }), 401

  connection = get_db_connection()

  if connection:
    try:
      with connection.cursor() as cursor:
        # Get the email from the "signedin" table based on the provided JWT token
        cursor.execute("SELECT email FROM signedin WHERE jwt_token = %s",
                       (jwt_token, ))
        result = cursor.fetchone()

        if not result:
          return jsonify({
              'status': 'error',
              'error_content': 'Invalid JWT token'
          }), 401

        email = result[0]

        # Get a list of all JWT tokens of that particular email
        cursor.execute("SELECT jwt_token FROM signedin WHERE email = %s",
                       (email, ))
        jwt_tokens = [row[0] for row in cursor.fetchall()]

        # Get all the outline_id and status from the "outline" table for each JWT token
        user_outlines = []
        for token in jwt_tokens:
          cursor.execute(
              "SELECT outline_id, status,title,visibility, goal, endafterdate, endafterresponses FROM polls WHERE jwt_token = %s",
              (token, ))
          outlines_data = cursor.fetchall()

          for outline_data in outlines_data:
            input_date = outline_data[5]

            if isinstance(input_date, (date, datetime)):
              formatted_date = input_date.strftime("%d %b %Y")

            else:
              # If it's a string, then use strptime and strftime
              try:
                parsed_date = datetime.strptime(input_date,
                                                "%a, %d %b %Y %H:%M:%S %Z")
                formatted_date = parsed_date.strftime("%d %b %Y")

              except ValueError as e:
                print(f"Error parsing date {input_date}: {e}")
            user_outlines.append({
                'outline_id': outline_data[0],
                'status': outline_data[1],
                'title': outline_data[2],
                'visibility': outline_data[3],
                'goal': outline_data[4],
                'endafterdate': formatted_date,
                'endafterresponses': outline_data[6],
                'lengthtime': '10 min',
                'lengthquestions': '7 ques'
            })

      return jsonify({
          'status': 'success',
          'user_outlines': user_outlines
      }), 200

    except Exception as e:
      print(f"Error: {str(e)}")
      return jsonify({
          'status':
          'error',
          'error_content':
          f'Failed to retrieve user outlines. Error: {str(e)}'
      }), 500

    finally:
      connection.close()

  return jsonify({
      'status': 'error',
      'error_content': 'Unable to connect to the database'
  }), 500


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=3000)
