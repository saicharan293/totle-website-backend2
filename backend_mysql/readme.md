
Required installations through console:

    npm init -y
    npm i dotenv mongoose express bcrypt jsonwebtoken express-rate-limit sequelize passport-google-oauth20

Mongo db set up:
    1.sign into mongodb.com with google
    2.Create a cluster and store the password since needed for authorization to databases
    3.create a database with appropriate name and also create a collection (table) with a name
    4.click on connect in the cluster and Mongo db for vs code
    5.copy the connect string provided in the 3rd option , follow the instructions given in the window and click on done
    6.paste that connect string in a '.env' file with named 'MONGO_URL' and give the collection name same as in the Mongodb atlas


Google integration:

    1.Search for Google Cloud Console
    2.Create a new project.
    3.Navigate to APIs & Services > Credentials.
    4.Create new OAuth credentials 
    5.On the same page, to the right, you can find Client Id and Client Secret which are essentials and store them in a same place
    6.set the appropriate redirect URI(http://localhost:3000/auth/google/callback in this case)



api's:
    localhost:5000/google/signup
    localhost:5000/signup-user
    localhost:5000/login

My Sql setup:

    npm install mysql2