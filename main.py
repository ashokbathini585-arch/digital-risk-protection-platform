from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from app_detection.detector import detect_app
from social_detection.backend.social.detectors.username import username_similarity
from social_detection.backend.social.detectors.display_name import display_name_similarity
from social_detection.backend.social.detectors.bio import bio_similarity
from social_detection.backend.social.detectors.lookalike import lookalike_score
from social_detection.backend.social.detectors.scam import scam_score
from social_detection.backend.social.detectors.logo import logo_similarity
from social_detection.backend.social.risk_engine import calculate_risk
app=FastAPI(title='NEXORA Digital Risk Protection API',version='2.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
class SocialScanRequest(BaseModel):
 platform:str; official_username:str; official_display_name:str; official_bio:str; candidate_username:str; candidate_display_name:str; candidate_bio:str; official_logo:str|None=None; candidate_logo:str|None=None

class PublicInstagramProfile(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    display_name: str = Field(default="", max_length=200)
    bio: str = Field(default="", max_length=2000)
    profile_url: str = Field(default="", max_length=500)
    verified_badge_observed: bool = False
    linked_from_official_website: bool = False
    followers: int | None = Field(default=None, ge=0)
    following: int | None = Field(default=None, ge=0)
    posts: int | None = Field(default=None, ge=0)

class InstagramCompareRequest(BaseModel):
    platform: str = "Instagram"
    profile_a: PublicInstagramProfile
    profile_b: PublicInstagramProfile

class AppScanRequest(BaseModel):
 app_name:str; developer:str; package_id:str; description:str=''
scanned_apps=[]
@app.get('/')
def home(): return {'success':True,'message':'NEXORA API is running','services':['social-detection','app-detection']}
@app.get('/health')
def health(): return {'status':'ok'}
@app.post('/social/scan')
def social_scan(data:SocialScanRequest):
 if data.candidate_username.lower().strip()==data.official_username.lower().strip(): return {'platform':data.platform,'status':'OFFICIAL','risk_score':0,'risk_level':'LOW','reasons':['Candidate account matches the official username']}
 u=username_similarity(data.official_username,data.candidate_username); d=display_name_similarity(data.official_display_name,data.candidate_display_name); b=bio_similarity(data.official_bio,data.candidate_bio); l=lookalike_score(data.official_username,data.candidate_username); scam=scam_score(data.candidate_bio); logo=logo_similarity(data.official_logo,data.candidate_logo) if data.official_logo and data.candidate_logo else 0
 r=calculate_risk(u,d,b,logo,l,scam['score']); reasons=[]
 if u>=70: reasons.append('Username strongly resembles the official account')
 if d>=70: reasons.append('Display name is highly similar')
 if b>=70: reasons.append('Bio is highly similar to the official account')
 if logo>=70: reasons.append('Profile logo is similar to the official logo')
 if l==100: reasons.append('Look-alike username detected')
 if scam['matched_keywords']: reasons.append('Suspicious scam language detected')
 if not reasons: reasons.append('No strong impersonation indicators detected')
 return {'platform':data.platform,'status':'SUSPICIOUS' if r['risk_score']>=50 else 'LOW_RISK','risk_score':r['risk_score'],'risk_level':r['risk_level'],'similarity':{'username':u,'display_name':d,'bio':b,'logo':logo,'lookalike':l},'scam_score':scam['score'],'reasons':reasons}

@app.post('/social/compare')
def compare_instagram(data: InstagramCompareRequest):
    """Compare user-supplied public Instagram profile observations. Does not scrape Instagram or verify claims."""
    from difflib import SequenceMatcher
    import re

    a, b = data.profile_a, data.profile_b
    def norm(value: str) -> str:
        return re.sub(r'[^a-z0-9]', '', (value or '').lower())
    def sim(x: str, y: str) -> float:
        x, y = norm(x), norm(y)
        return round(100 * SequenceMatcher(None, x, y).ratio(), 1) if x and y else 0.0
    def profile_risk(p, other):
        score = 0.0; reasons = []; evidence = []
        user_sim = sim(p.username, other.username)
        name_sim = sim(p.display_name, other.display_name)
        bio_sim = sim(p.bio, other.bio)
        if user_sim >= 75 and norm(p.username) != norm(other.username):
            score += 30; reasons.append('Username closely resembles the other profile')
        if name_sim >= 80 and p.display_name and other.display_name:
            score += 15; reasons.append('Display name closely resembles the other profile')
        if bio_sim >= 75 and p.bio and other.bio:
            score += 10; reasons.append('Bio is very similar to the other profile')
        scam = scam_score(p.bio or '')
        if scam.get('score', 0) >= 20:
            score += min(25, scam['score'] * 0.25); reasons.append('Bio contains potential scam or credential-request language')
        if p.followers is not None and p.following is not None and p.following >= 100 and p.followers < 10:
            score += 5; reasons.append('Very low followers compared with following count (weak signal only)')
        if p.verified_badge_observed:
            score -= 20; evidence.append('User reports a visible verification badge; badge status was not independently checked')
        if p.linked_from_official_website:
            score -= 35; evidence.append('User reports this profile is linked from an official website; link was not independently checked')
        return max(0, min(100, round(score))), reasons, evidence, {'username': user_sim, 'display_name': name_sim, 'bio': bio_sim, 'scam_score': scam.get('score', 0)}

    risk_a, reasons_a, evidence_a, similarity_a = profile_risk(a, b)
    risk_b, reasons_b, evidence_b, similarity_b = profile_risk(b, a)
    # A defensible original-account claim needs trusted-source evidence, not only similarity or follower counts.
    trust_a = int(a.linked_from_official_website) * 2 + int(a.verified_badge_observed)
    trust_b = int(b.linked_from_official_website) * 2 + int(b.verified_badge_observed)
    gap = abs(risk_a - risk_b)
    if trust_a >= 2 and trust_a > trust_b and risk_b >= risk_a:
        verdict = 'PROFILE_A_LIKELY_ORIGINAL_PROFILE_B_SUSPICIOUS'; confidence = 'moderate' if gap >= 10 else 'low'
        label_a, label_b = 'Likely original (reported trusted evidence)', 'More suspicious — review carefully'
    elif trust_b >= 2 and trust_b > trust_a and risk_a >= risk_b:
        verdict = 'PROFILE_B_LIKELY_ORIGINAL_PROFILE_A_SUSPICIOUS'; confidence = 'moderate' if gap >= 10 else 'low'
        label_a, label_b = 'More suspicious — review carefully', 'Likely original (reported trusted evidence)'
    elif gap >= 25 and max(risk_a, risk_b) >= 35:
        verdict = 'RELATIVE_RISK_ONLY'; confidence = 'low'; label_a = 'Unconfirmed'; label_b = 'Unconfirmed'
        if risk_a > risk_b:
            label_a, label_b = 'More suspicious relative to Profile B', 'Lower risk relative to Profile A (not verified)'
        else:
            label_a, label_b = 'Lower risk relative to Profile B (not verified)', 'More suspicious relative to Profile A'
    else:
        verdict = 'INSUFFICIENT_EVIDENCE'; confidence = 'low'; label_a = 'Insufficient evidence'; label_b = 'Insufficient evidence'
    return {
        'platform': 'Instagram', 'verdict': verdict, 'confidence': confidence,
        'profile_a': {'username': a.username, 'risk_score': risk_a, 'verdict': label_a, 'reasons': reasons_a, 'supporting_evidence': evidence_a, 'similarity': similarity_a},
        'profile_b': {'username': b.username, 'risk_score': risk_b, 'verdict': label_b, 'reasons': reasons_b, 'supporting_evidence': evidence_b, 'similarity': similarity_b},
        'comparison_reasons': (['Profiles have a large difference in heuristic risk indicators; this is relative risk, not proof of authenticity.'] if gap >= 25 else ['Public details do not establish a reliable original-account winner.']),
        'limitations': ['This endpoint uses information manually entered by the user; it does not fetch or authenticate Instagram data.', 'Verification badge, official-website link, follower counts and profile details were not independently checked.', 'A verified badge does not prove every post or message is safe; follower counts and profile similarity are weak signals.', 'Confirm by opening the profile from the organisation/person’s independently known official website or contacting them through a trusted channel.']
    }

@app.post('/apps/scan')
def scan_app(request:AppScanRequest):
 result=detect_app(request.model_dump()); scanned_apps.append(result); return {'success':True,'data':result}
@app.get('/apps')
def get_apps(): return {'success':True,'total':len(scanned_apps),'apps':scanned_apps}
