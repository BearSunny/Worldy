from pymongo import MongoClient

client = MongoClient("mongodb+srv://minh:RlQqxKyuAhhhms4C@cluster0.mongodb.net/test?retryWrites=true&w=majority")
db = client.user_data
print("Connected to MongoDB Atlas!")
