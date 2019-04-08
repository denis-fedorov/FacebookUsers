# FacebookUsers
A sample app for store users with Facebook authentication

## How to run
1. Run a deployment script (_Deployment\generate_tables.sql_) in SQL Server - it creates the **FacebookUsersDb** and all necessary tables
2. Accordingly update a path to the database in the **DefaultConnection** parameter in the _appSettings.json_ file
3. Update **Authentication** section with your _AppId_ and _AppSecret_ for you Facebook connection (if necessary).
