from reputation_service import ReputationDB, reputation_service

db = ReputationDB()
rep = reputation_service(db, "162.240.214.62")
print(rep)
rep = reputation_service(db, "169.254.10.20")
print(rep)
rep = reputation_service(db, "203.0.113.10")
print(rep)
rep = reputation_service(db, "8.8.8.8")
print(rep)
