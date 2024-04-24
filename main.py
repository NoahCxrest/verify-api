import flask
from flask import Flask, request, redirect, url_for, render_template
import requests
import pymongo
from decouple import config


client = pymongo.MongoClient(config('MONGO_URL'))
db = client['erm']
coll = db['oauth2']
pending_coll = db['pending_oauth2']
app = Flask(__name__)

@app.route('/auth')
def auth():
    code = request.args.get('code')
    discord_id = request.args.get('state')
    if pending_coll.find_one({'discord_id': discord_id}) is None:
        return 'You have not started a OAuth2 session. If this is invalid, please contact ERM Support.'
    
    req = requests.post("https://apis.roblox.com/oauth/v1/token", data={
        "client_id": int(config('CLIENT_ID')),
        "client_secret": config("CLIENT_SECRET"),
        "grant_type": "authorization_code",
        "code": code
    }, headers={
        "Content-Type": "application/x-www-form-urlencoded"
    })
    access_token = req.json()['access_token']
    new_req = requests.get("https://apis.roblox.com/oauth/v1/userinfo", headers={
        "Authorization": f"Bearer {access_token}"
    })
    if coll.find_one({ "discord_id": discord_id }):
        coll.update_one(
            { 'discord_id': discord_id },
            {"$set": { "roblox_id": new_req.json()["sub"]}}
        )
    else:
        coll.insert_one({
            "discord_id": discord_id,
            "roblox_id": new_req.json()["sub"]
        })
    return redirect(url_for('finished', username=new_req.json()['preferred_username']))

@app.route('/finished')
def finished():
    username = request.args.get('username')
    return render_template('finished.html', username=username)

app.run(port=80, debug=False)


