class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable#, :authentication_keys => [:login]



	has_many :user_roles
  	has_many :roles, through: :user_roles

	attr_accessor :login, :LanId
	# attr_accessible :LanId


	def login=(login)
		@login = login
	end

	def login
		@login || self.LanId || self.email
	end

	before_save do 
		self.LanId = SecureRandom.hex
	end

	def self.find_for_database_authentication warden_conditions
	  conditions = warden_conditions.dup
	  login = conditions.delete(:login)
	  where(conditions).where(["lower(LanId) = :value OR lower(email) = :value", {value: login.strip.downcase}]).first
	end

end
