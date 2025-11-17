# Fix Uncorrect Threat Level
-> Londer.be = "High" but is safe and legit
-> silkytravel.uk.com = "Medium" or "Low" but is actually a phishing used domain

# Check mail verification

# Improve the returns "errors" handling
-> when having an unexpected error from an API call (http-code or other type of error), having according handling to have a logic score throughout tests

# Add more "extern" verification services 
-> improve the result (more data)

# Add a "local" database for data storing
-> Redis/SQLite/PostgreSQL/other ? 
-> Some data may need to be permanent other not (cache or not)

# (Visual) Improve the handling of the CLI interface (loading, etc...)

# (Visual) Add an HTML/CSS response mode for the our API response

# Add machine learning (maybe ?)
-> could be useful for "phishing" type of email, or suspicious domain.
-> BUT ask way more performance... maybe a special mode/flag/route ?
-> specific Vector type Database for ML ?