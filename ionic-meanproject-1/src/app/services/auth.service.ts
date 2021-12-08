import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { User, Login, UserNoPW } from '../models/User';
import { JwtHelperService } from '@auth0/angular-jwt';


const httpOptions = {
headers: new HttpHeaders({
  contentType: 'application/json',
}),
};

@Injectable({
providedIn: 'root',
})

export class AuthService {
authToken: any;
user: User;

constructor(private http: HttpClient, public jwtHelper: JwtHelperService ) {}

prepEndpoint(ep) {
  // 1. 로컬 서버에서 개발시
  // 'http://localhost:3000/' + ep;
  // 2. 클라우드 서버에서 운영시
  //return ep;
  // 3. Ionic app 개발시 클라우드 서비스 주소 이용
   return 'https://mean91514658.herokuapp.com/' + ep;

}


registerUser(user): Observable<any> {
const registerUrl = this.prepEndpoint('users/register');
return this.http.post(registerUrl, user, httpOptions);
}

authenticateUser(login: Login): Observable<any> {
  const loginUrl = this.prepEndpoint('users/authenticate');
  return this.http.post<any>(loginUrl, login, httpOptions);
}

storeUserData(token: any, userNoPW: UserNoPW) {
  localStorage.setItem('authToken', token);
  localStorage.setItem('userNoPW', JSON.stringify(userNoPW));
  }
logout() {
    // localStorage.clear();
    localStorage.removeItem('authToken');
    localStorage.removeItem('userNoPW');
  }
getProfile(): Observable<any> {
  const authToken: any = localStorage.getItem('authToken');
    // 토큰을 포함한 헤더 옵션 생성
    const httpOptions1 = {
    headers: new HttpHeaders({
    'Content-Type': 'application/json', 
    authorization: 'Bearer ' + authToken,
    }),
    };
    const profileUrl = this.prepEndpoint('users/profile');
    return this.http.get<any>(profileUrl, httpOptions1);
  }
  
loggedIn(): boolean {
  const authToken: any = localStorage.getItem('authToken');
    return !this.jwtHelper.isTokenExpired(authToken);
  }

}