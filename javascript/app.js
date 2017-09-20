const angularModule = angular.module('nodeAuth', [
    'ngRoute'
]);
angularModule.config(['$locationProvider', '$routeProvider', '$httpProvider',
    function ($locationProvider, $routeProvider, $httpProvider) {
        $locationProvider.html5Mode(true);
        $routeProvider.when('/', {
            templateUrl: '/views/home.html'
        }).when('/signin', {
            templateUrl: '/views/signin.html'
        }).when('/profile', {
            templateUrl: '/views/profile.html'
        }).when('/401', {
            templateUrl: '/views/401.html'
        }).otherwise({
            redirectTo: '/'
        });
        $httpProvider.interceptors.push(['$rootScope', '$q', '$location', function ($rootScope, $q, $location) {
            return {
                request: function (config) {
                    if (localStorage.getItem('auth-token')) {
                        config.headers.Authorization = 'bearer ' + localStorage.getItem('auth-token');
                    }
                    return config;
                },
                response: function (response) {
                    if (response.headers('X-Access-Token')) {
                        localStorage.setItem('auth-token', response.headers('X-Access-Token'));
                    }
                    return response;
                },
                responseError: function (res) {
                    if (res.status === 401) {
                        $location.url('/signin');
                    }
                    return $q.reject(res);
                }
            };
        }]);
    }
]);
angularModule.run(['$rootScope', '$http',
    function ($rootScope, $http) {
        if (localStorage.getItem('auth-token') && !$rootScope.username) {
            return $http.post('/keepsession', {}).then((res) => {
                $rootScope.username = res.data.user;
            }, () => {
                localStorage.removeItem('auth-token');
            });
        }
    }
]);
angularModule.controller('userController', ['$rootScope', '$scope',
    function ($rootScope, $scope) {
        $scope.signIn = function (valid) {
            if (!valid) {
                $scope.formError = true;
            } else {
                $scope.formError = false;
                $http.post('/signin', {
                    email: $scope.form.email,
                    password: $scope.form.password
                }).then((res) => {
                    localStorage.setItem('auth-token', res.data.token);
                    $rootScope.username = res.data.username;
                }, () => {
                    $scope.signinForm.email = '';
                    $scope.signinForm.password = '';
                    $scope.formError = true;
                });
            }
        };
    }
]);
angularModule.controller('profileController', ['$scope', '$http',
    function ($scope, $http) {
        return $http.post('/profile', {}).then((res) => {
            $scope.realName = res.data.realName;
        });
    }
]);