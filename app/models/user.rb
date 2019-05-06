class User < ApplicationRecord
    attr_accessor :remember_token
    validates:name,presence:true
    validates :email, presence: true
    validates:name,presence:true,length:{maximum:50}
    validates:email,presence:true,length:{maximum:255}
    validates:name,presence:true,length:{maximum:50}
    VALID_EMAIL_REGEX=/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
    validates:email,presence:true,length:{maximum:255},format:{with:VALID_EMAIL_REGEX}
    validates:email,presence:true,length:{maximum:255},format:{with:VALID_EMAIL_REGEX},uniqueness:{case_sensitive:false}
    before_save { self.email = self.email.downcase }
    has_secure_password
     validates :password, presence: true, length: { minimum: 6 }, allow_nil: true
    
    def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
    end
    
    def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
    end
    
    def User.new_token
    SecureRandom.urlsafe_base64
    end
    
    def self.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
    end
    
    def self.new_token
    SecureRandom.urlsafe_base64
    end
    
    class << self
    # Returns the hash digest of the given string.
    def digest(string)
      cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                    BCrypt::Engine.cost
      BCrypt::Password.create(string, cost: cost)
    end

    # Returns a random token.
    def new_token
      SecureRandom.urlsafe_base64
    end
    end
    
    def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
    end
    
    def forget
    update_attribute(:remember_digest, nil)
    end
  
end
